package pgconn

import "core:crypto"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:crypto/pbkdf2"
import "core:encoding/base64"
import "core:strconv"
import "core:strings"
import "../pgerr"

Scram_State :: struct {
	client_nonce:      string,
	combined_nonce:    string,
	salt:              []byte,
	iterations:        int,
	client_first_bare: string,
	server_first:      string,
	auth_message:      string,
	server_signature:  [32]byte,
}

/*
	scram_escape_username escapes ',' -> '=2C' and '=' -> '=3D' per RFC 5802.
*/
scram_escape_username :: proc(user: string, allocator := context.temp_allocator) -> string {
	b := strings.builder_make(allocator)
	for i in 0 ..< len(user) {
		ch := user[i]
		if ch == ',' {
			strings.write_string(&b, "=2C")
		} else if ch == '=' {
			strings.write_string(&b, "=3D")
		} else {
			strings.write_byte(&b, ch)
		}
	}
	return strings.to_string(b)
}

/*
	scram_client_first initializes Scram_State and builds client-first-message.
*/
scram_client_first :: proc(
	state: ^Scram_State,
	user: string,
	injected_nonce := "",
	allocator := context.temp_allocator,
) -> (
	client_first_msg: string,
	err: pgerr.Error,
) {
	if len(injected_nonce) > 0 {
		state.client_nonce = strings.clone(injected_nonce, allocator)
	} else {
		// Generate 24 random bytes -> 32 base64 characters
		raw_nonce: [24]byte
		crypto.rand_bytes(raw_nonce[:])
		b64_nonce := base64.encode(raw_nonce[:], allocator = allocator)
		state.client_nonce = b64_nonce
	}

	escaped_user := scram_escape_username(user, context.temp_allocator)

	// client-first-message-bare = "n=" + escaped_user + ",r=" + client_nonce
	bare_builder := strings.builder_make(allocator)
	strings.write_string(&bare_builder, "n=")
	strings.write_string(&bare_builder, escaped_user)
	strings.write_string(&bare_builder, ",r=")
	strings.write_string(&bare_builder, state.client_nonce)
	state.client_first_bare = strings.to_string(bare_builder)

	// client-first-message = "n,," + client-first-message-bare
	full_builder := strings.builder_make(allocator)
	strings.write_string(&full_builder, "n,,")
	strings.write_string(&full_builder, state.client_first_bare)

	return strings.to_string(full_builder), nil
}

/*
	scram_parse_server_first parses attribute list from server-first-message (r=, s=, i=).
*/
scram_parse_server_first :: proc(
	server_first: string,
	allocator := context.temp_allocator,
) -> (
	nonce: string,
	salt: []byte,
	iterations: int,
	err: pgerr.Error,
) {
	parts := strings.split(server_first, ",", context.temp_allocator)
	var_nonce := ""
	var_salt_b64 := ""
	var_iter := 0

	for part in parts {
		if len(part) < 2 || part[1] != '=' do continue
		key := part[0]
		val := part[2:]
		switch key {
		case 'r':
			var_nonce = val
		case 's':
			var_salt_b64 = val
		case 'i':
			iter_val, ok := strconv.parse_int(val)
			if ok && iter_val > 0 {
				var_iter = iter_val
			}
		}
	}

	if len(var_nonce) == 0 || len(var_salt_b64) == 0 || var_iter <= 0 {
		return "", nil, 0, pgerr.Auth_Error{
			type = .SCRAM_Invalid_Server_First_Message,
			message = "Missing or invalid fields in SCRAM server-first message",
		}
	}

	decoded_salt, decode_err := base64.decode(var_salt_b64, allocator = allocator)
	if decode_err != nil {
		return "", nil, 0, pgerr.Auth_Error{
			type = .SCRAM_Invalid_Server_First_Message,
			message = "Failed to decode base64 salt in SCRAM server-first message",
		}
	}

	return var_nonce, decoded_salt, var_iter, nil
}

/*
	scram_client_final parses server-first-message, performs PBKDF2/HMAC key derivation,
	calculates ClientProof, and constructs client-final-message.
*/
scram_client_final :: proc(
	state: ^Scram_State,
	server_first_msg: string,
	password: string,
	allocator := context.temp_allocator,
) -> (
	client_final_msg: string,
	err: pgerr.Error,
) {
	r_nonce, salt, iterations, parse_err := scram_parse_server_first(server_first_msg, allocator)
	if parse_err != nil {
		return "", parse_err
	}

	// Verify server nonce begins with client nonce
	if !strings.has_prefix(r_nonce, state.client_nonce) {
		delete(salt, allocator)
		return "", pgerr.Auth_Error{
			type = .SCRAM_Invalid_Server_First_Message,
			message = "Server nonce does not match client nonce",
		}
	}

	state.combined_nonce = strings.clone(r_nonce, allocator)
	state.salt = salt
	state.iterations = iterations
	state.server_first = strings.clone(server_first_msg, allocator)

	// client-final-message-without-proof = "c=biws,r=" + combined_nonce
	client_final_without_proof := strings.concatenate(
		{"c=biws,r=", state.combined_nonce},
		context.temp_allocator,
	)

	// auth-message = client-first-message-bare + "," + server-first + "," + client-final-message-without-proof
	state.auth_message = strings.concatenate(
		{state.client_first_bare, ",", state.server_first, ",", client_final_without_proof},
		allocator,
	)

	// SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations)
	salted_password: [32]byte
	pbkdf2.derive(
		.SHA256,
		transmute([]byte)password,
		state.salt,
		u32(state.iterations),
		salted_password[:],
	)

	// ClientKey = HMAC-SHA256(SaltedPassword, "Client Key")
	client_key: [32]byte
	hmac.sum(.SHA256, client_key[:], transmute([]byte)string("Client Key"), salted_password[:])

	// StoredKey = SHA256(ClientKey)
	stored_key: [32]byte
	hash.hash(.SHA256, client_key[:], stored_key[:])

	// ClientSignature = HMAC-SHA256(StoredKey, auth-message)
	client_signature: [32]byte
	hmac.sum(.SHA256, client_signature[:], transmute([]byte)state.auth_message, stored_key[:])

	// ClientProof = ClientKey XOR ClientSignature
	client_proof: [32]byte
	for i in 0 ..< 32 {
		client_proof[i] = client_key[i] ~ client_signature[i]
	}

	// ServerKey = HMAC-SHA256(SaltedPassword, "Server Key")
	server_key: [32]byte
	hmac.sum(.SHA256, server_key[:], transmute([]byte)string("Server Key"), salted_password[:])

	// ServerSignature = HMAC-SHA256(ServerKey, auth-message)
	hmac.sum(.SHA256, state.server_signature[:], transmute([]byte)state.auth_message, server_key[:])

	// Base64 encode ClientProof
	b64_proof := base64.encode(client_proof[:], allocator = context.temp_allocator)

	// client-final-message = client_final_without_proof + ",p=" + b64_proof
	result := strings.concatenate({client_final_without_proof, ",p=", b64_proof}, allocator)
	return result, nil
}

/*
	scram_verify_server_final extracts v= attribute from server-final-message
	and compares against state.server_signature.
*/
scram_verify_server_final :: proc(
	state: ^Scram_State,
	server_final_msg: string,
	allocator := context.temp_allocator,
) -> pgerr.Error {
	parts := strings.split(server_final_msg, ",", context.temp_allocator)
	var_v_b64 := ""

	for part in parts {
		if len(part) >= 2 && part[0] == 'v' && part[1] == '=' {
			var_v_b64 = part[2:]
		} else if len(part) >= 2 && part[0] == 'e' && part[1] == '=' {
			return pgerr.Auth_Error{
				type = .Authentication_Failed,
				message = strings.clone(part[2:], allocator),
			}
		}
	}

	if len(var_v_b64) == 0 {
		return pgerr.Auth_Error{
			type = .SCRAM_Invalid_Server_Final_Message,
			message = "Missing v= signature in SCRAM server-final message",
		}
	}

	decoded_sig, decode_err := base64.decode(var_v_b64, allocator = context.temp_allocator)
	if decode_err != nil || len(decoded_sig) != 32 {
		return pgerr.Auth_Error{
			type = .SCRAM_Invalid_Server_Final_Message,
			message = "Invalid base64 signature in SCRAM server-final message",
		}
	}

	// Compare decoded signature with state.server_signature in constant time
	matches := true
	for i in 0 ..< 32 {
		if decoded_sig[i] != state.server_signature[i] {
			matches = false
		}
	}

	if !matches {
		return pgerr.Auth_Error{
			type = .SCRAM_Server_Signature_Mismatch,
			message = "Server SCRAM signature mismatch",
		}
	}

	return nil
}


package pgconn

import "core:crypto"
import "core:encoding/base64"
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

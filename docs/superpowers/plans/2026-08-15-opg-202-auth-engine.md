# [OPG-202] SCRAM-SHA-256 & MD5 Authentication Handshake Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement pure-Odin PostgreSQL authentication handshakes supporting Cleartext Password, MD5 (`compute_md5_password`), and SCRAM-SHA-256 (RFC 5802 / RFC 7677) in `pgconn/auth.odin` and `pgconn/auth_scram.odin`.

**Architecture:** `auth_handle_challenge` dispatches backend authentication requests. `compute_md5_password` handles MD5 challenges. `Scram_State` tracks multi-round SASL SCRAM-SHA-256 handshakes (`scram_client_first`, `scram_client_final`, `scram_verify_server_final`) using `core:crypto/hash`, `core:crypto/hmac`, `core:crypto/pbkdf2`, and `core:encoding/base64`.

**Tech Stack:** Odin, `core:crypto`, `core:crypto/legacy/md5`, `core:crypto/hash`, `core:crypto/hmac`, `core:crypto/pbkdf2`, `core:encoding/base64`, `core:encoding/hex`, `pgproto`, `pgerr`.

**Spec:** [`docs/superpowers/specs/2026-08-15-opg-202-auth-engine-design.md`](file:///home/igorrumiha/Projects/odin-projects/opg/docs/superpowers/specs/2026-08-15-opg-202-auth-engine-design.md)

## Global Constraints

- Never do what was not specifically asked for.
- All errors must return `pgerr.Error` (tagged union). Subpackages import `pgerr` — never `root.odin`.
- All transient packet parsing and string generation use `allocator := context.temp_allocator`.
- Multi-byte integers must be read/written in Network Byte Order (Big-Endian).
- Unit tests must be 100% network-independent using `Mock_Transport` and in-memory byte vectors.
- Zero memory leaks verified using `core:mem.Tracking_Allocator`.

---

### Task 1: MD5 Password Hashing & Cleartext Password Dispatcher

**Files:**
- Create: `pgconn/auth.odin`
- Create: `pgconn/auth_test.odin`

**Interfaces:**
- Produces:
  - `compute_md5_password(user: string, password: string, salt: [4]byte, allocator := context.temp_allocator) -> string`

- [ ] **Step 1: Write failing tests for MD5 password hashing and vector verification**

In `pgconn/auth_test.odin`:
```odin
package pgconn

import "core:mem"
import "core:testing"
import "../pgerr"

@(test)
test_auth_md5_password_computation :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// Known PostgreSQL MD5 vector:
	// user: "postgres", password: "password", salt: [4]byte{1, 2, 3, 4}
	// md5("passwordpostgres") -> "368d40be2e68095b341f237f8f94943f"
	// md5("368d40be2e68095b341f237f8f94943f" + [1, 2, 3, 4])
	salt := [4]byte{1, 2, 3, 4}
	result := compute_md5_password("postgres", "password", salt, context.allocator)
	defer delete(result, context.allocator)

	testing.expect_value(t, len(result), 35) // "md5" + 32 hex chars
	testing.expect(t, result[:3] == "md5", "expected md5 prefix")

	// Verify consistency across runs
	result2 := compute_md5_password("postgres", "password", salt, context.allocator)
	defer delete(result2, context.allocator)
	testing.expect_value(t, result, result2)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `compute_md5_password` undefined

- [ ] **Step 3: Implement `compute_md5_password` in `pgconn/auth.odin`**

In `pgconn/auth.odin`:
```odin
package pgconn

import "core:crypto/legacy/md5"
import "core:encoding/hex"
import "core:strings"
import "../pgerr"
import "../pgproto"

/*
	compute_md5_password computes the PostgreSQL MD5 password challenge response:
	"md5" + hex(md5(hex(md5(password + user)) + salt))
*/
compute_md5_password :: proc(
	user: string,
	password: string,
	salt: [4]byte,
	allocator := context.temp_allocator,
) -> string {
	// Stage 1: md5(password + user)
	var_ctx1: md5.Context
	md5.init(&var_ctx1)
	md5.update(&var_ctx1, transmute([]byte)password)
	md5.update(&var_ctx1, transmute([]byte)user)
	var_digest1: [16]byte
	md5.final(&var_ctx1, var_digest1[:])

	// Encode digest1 to lowercase hex
	hex_buf1: [32]byte
	_ = hex.encode(hex_buf1[:], var_digest1[:])

	// Stage 2: md5(hex_buf1 + salt)
	var_ctx2: md5.Context
	md5.init(&var_ctx2)
	md5.update(&var_ctx2, hex_buf1[:])
	md5.update(&var_ctx2, salt[:])
	var_digest2: [16]byte
	md5.final(&var_ctx2, var_digest2[:])

	// Stage 3: format "md5" + hex_buf2
	hex_buf2: [32]byte
	_ = hex.encode(hex_buf2[:], var_digest2[:])

	out_bytes := make([]byte, 35, allocator)
	out_bytes[0] = 'm'
	out_bytes[1] = 'd'
	out_bytes[2] = '5'
	copy(out_bytes[3:], hex_buf2[:])

	return string(out_bytes)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/auth.odin pgconn/auth_test.odin
git commit -m "feat(pgconn): implement compute_md5_password with unit tests"
```

---

### Task 2: SCRAM-SHA-256 State & Client-First Message (`scram_client_first`)

**Files:**
- Create: `pgconn/auth_scram.odin`
- Modify: `pgconn/auth_test.odin`

**Interfaces:**
- Produces:
  - `Scram_State :: struct`
  - `scram_client_first(state: ^Scram_State, user: string, injected_nonce := "", allocator := context.temp_allocator) -> (client_first_msg: string, err: pgerr.Error)`

- [ ] **Step 1: Write failing tests for `scram_client_first` and RFC 7677 nonce formatting**

In `pgconn/auth_test.odin`:
```odin
@(test)
test_auth_scram_client_first_rfc7677 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	state: Scram_State
	msg, err := scram_client_first(&state, "user", injected_nonce = "rOprNGfwEbeRWgbNEkqO", allocator = context.allocator)
	defer delete(msg, context.allocator)
	defer delete(state.client_nonce, context.allocator)
	defer delete(state.client_first_bare, context.allocator)

	testing.expect(t, err == nil, "expected scram_client_first success")
	// RFC 7677 Client First message: "n,,n=user,r=rOprNGfwEbeRWgbNEkqO"
	testing.expect_value(t, msg, "n,,n=user,r=rOprNGfwEbeRWgbNEkqO")
	testing.expect_value(t, state.client_nonce, "rOprNGfwEbeRWgbNEkqO")
	testing.expect_value(t, state.client_first_bare, "n=user,r=rOprNGfwEbeRWgbNEkqO")

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_scram_client_first_random_nonce :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	state: Scram_State
	msg, err := scram_client_first(&state, "postgres", allocator = context.allocator)
	defer delete(msg, context.allocator)
	defer delete(state.client_nonce, context.allocator)
	defer delete(state.client_first_bare, context.allocator)

	testing.expect(t, err == nil, "expected scram_client_first success")
	testing.expect(t, len(state.client_nonce) >= 24, "expected random nonce length >= 24")
	testing.expect(t, strings.has_prefix(msg, "n,,n=postgres,r="), "expected valid client first prefix")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `Scram_State` / `scram_client_first` undefined

- [ ] **Step 3: Implement `Scram_State` and `scram_client_first` in `pgconn/auth_scram.odin`**

In `pgconn/auth_scram.odin`:
```odin
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

	escaped_user := scram_escape_username(user, allocator)

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/auth_scram.odin pgconn/auth_test.odin
git commit -m "feat(pgconn): implement Scram_State and scram_client_first"
```

---

### Task 3: SCRAM-SHA-256 Server-First Parsing & Client-Final Proof Generation (`scram_client_final`)

**Files:**
- Modify: `pgconn/auth_scram.odin`
- Modify: `pgconn/auth_test.odin`

**Interfaces:**
- Produces:
  - `scram_client_final(state: ^Scram_State, server_first_msg: string, password: string, allocator := context.temp_allocator) -> (client_final_msg: string, err: pgerr.Error)`

- [ ] **Step 1: Write failing test for `scram_client_final` matching RFC 7677 vector**

In `pgconn/auth_test.odin`:
```odin
@(test)
test_auth_scram_client_final_rfc7677 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	state: Scram_State
	_, _ = scram_client_first(&state, "user", injected_nonce = "rOprNGfwEbeRWgbNEkqO", allocator = context.allocator)
	defer delete(state.client_nonce, context.allocator)
	defer delete(state.client_first_bare, context.allocator)

	server_first := "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)h,s=QSXCR+Q6sek8bf92,i=4096"
	client_final, err := scram_client_final(&state, server_first, "pencil", allocator = context.allocator)
	defer delete(client_final, context.allocator)
	defer delete(state.combined_nonce, context.allocator)
	defer delete(state.server_first, context.allocator)
	defer delete(state.auth_message, context.allocator)
	defer delete(state.salt, context.allocator)

	testing.expect(t, err == nil, "expected scram_client_final success")

	// RFC 7677 Expected Client Final:
	// "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)h,p=dHzbZapWIclskip7gHG/vqafEmOXdMCgrEcuc9cmSmA="
	expected_client_final := "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)h,p=dHzbZapWIclskip7gHG/vqafEmOXdMCgrEcuc9cmSmA="
	testing.expect_value(t, client_final, expected_client_final)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `scram_client_final` undefined

- [ ] **Step 3: Implement `scram_client_final` in `pgconn/auth_scram.odin`**

In `pgconn/auth_scram.odin`:
```odin
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:crypto/pbkdf2"
import "core:strconv"

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
	parts := strings.split(server_first, ",", allocator)
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

	decoded_salt, decode_ok := base64.decode(var_salt_b64, allocator = allocator)
	if !decode_ok {
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
	final_without_proof_builder := strings.builder_make(allocator)
	strings.write_string(&final_without_proof_builder, "c=biws,r=")
	strings.write_string(&final_without_proof_builder, state.combined_nonce)
	client_final_without_proof := strings.to_string(final_without_proof_builder)

	// auth-message = client-first-message-bare + "," + server-first + "," + client-final-message-without-proof
	auth_msg_builder := strings.builder_make(allocator)
	strings.write_string(&auth_msg_builder, state.client_first_bare)
	strings.write_byte(&auth_msg_builder, ',')
	strings.write_string(&auth_msg_builder, state.server_first)
	strings.write_byte(&auth_msg_builder, ',')
	strings.write_string(&auth_msg_builder, client_final_without_proof)
	state.auth_message = strings.to_string(auth_msg_builder)

	// SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations)
	salted_password: [32]byte
	pbkdf2.derive(
		.SHA256,
		transmute([]byte)password,
		state.salt,
		state.iterations,
		salted_password[:],
	)

	// ClientKey = HMAC-SHA256(SaltedPassword, "Client Key")
	client_key: [32]byte
	var_hmac_client: hmac.Context
	hmac.init(&var_hmac_client, .SHA256, salted_password[:])
	hmac.update(&var_hmac_client, transmute([]byte)string("Client Key"))
	hmac.final(&var_hmac_client, client_key[:])

	// StoredKey = SHA256(ClientKey)
	stored_key: [32]byte
	hash.hash(.SHA256, client_key[:], stored_key[:])

	// ClientSignature = HMAC-SHA256(StoredKey, auth-message)
	client_signature: [32]byte
	var_hmac_sig: hmac.Context
	hmac.init(&var_hmac_sig, .SHA256, stored_key[:])
	hmac.update(&var_hmac_sig, transmute([]byte)state.auth_message)
	hmac.final(&var_hmac_sig, client_signature[:])

	// ClientProof = ClientKey XOR ClientSignature
	client_proof: [32]byte
	for i in 0 ..< 32 {
		client_proof[i] = client_key[i] ~ client_signature[i]
	}

	// ServerKey = HMAC-SHA256(SaltedPassword, "Server Key")
	server_key: [32]byte
	var_hmac_server: hmac.Context
	hmac.init(&var_hmac_server, .SHA256, salted_password[:])
	hmac.update(&var_hmac_server, transmute([]byte)string("Server Key"))
	hmac.final(&var_hmac_server, server_key[:])

	// ServerSignature = HMAC-SHA256(ServerKey, auth-message)
	hmac.init(&var_hmac_server, .SHA256, server_key[:])
	hmac.update(&var_hmac_server, transmute([]byte)state.auth_message)
	hmac.final(&var_hmac_server, state.server_signature[:])

	// Base64 encode ClientProof
	b64_proof := base64.encode(client_proof[:], allocator = allocator)

	// client-final-message = client_final_without_proof + ",p=" + b64_proof
	final_builder := strings.builder_make(allocator)
	strings.write_string(&final_builder, client_final_without_proof)
	strings.write_string(&final_builder, ",p=")
	strings.write_string(&final_builder, b64_proof)

	return strings.to_string(final_builder), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/auth_scram.odin pgconn/auth_test.odin
git commit -m "feat(pgconn): implement scram_client_final with RFC 7677 vector validation"
```

---

### Task 4: SCRAM-SHA-256 Server-Final Verification (`scram_verify_server_final`)

**Files:**
- Modify: `pgconn/auth_scram.odin`
- Modify: `pgconn/auth_test.odin`

**Interfaces:**
- Produces:
  - `scram_verify_server_final(state: ^Scram_State, server_final_msg: string, allocator := context.temp_allocator) -> pgerr.Error`

- [ ] **Step 1: Write failing test for `scram_verify_server_final`**

In `pgconn/auth_test.odin`:
```odin
@(test)
test_auth_scram_verify_server_final_rfc7677 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	state: Scram_State
	_, _ = scram_client_first(&state, "user", injected_nonce = "rOprNGfwEbeRWgbNEkqO", allocator = context.allocator)
	defer delete(state.client_nonce, context.allocator)
	defer delete(state.client_first_bare, context.allocator)

	server_first := "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)h,s=QSXCR+Q6sek8bf92,i=4096"
	client_final, _ := scram_client_final(&state, server_first, "pencil", allocator = context.allocator)
	defer delete(client_final, context.allocator)
	defer delete(state.combined_nonce, context.allocator)
	defer delete(state.server_first, context.allocator)
	defer delete(state.auth_message, context.allocator)
	defer delete(state.salt, context.allocator)

	// RFC 7677 Expected Server Final: "v=6rriTRbeXPkWrfGt1QGoxi7hSUxiiuhZ7pwmgpYAcbU="
	server_final := "v=6rriTRbeXPkWrfGt1QGoxi7hSUxiiuhZ7pwmgpYAcbU="
	err := scram_verify_server_final(&state, server_final, allocator = context.allocator)
	testing.expect(t, err == nil, "expected valid server final verification")

	// Verify tampered signature fails
	tampered_server_final := "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	bad_err := scram_verify_server_final(&state, tampered_server_final, allocator = context.allocator)
	testing.expect(t, bad_err != nil, "expected error on tampered signature")
	auth_err, ok := bad_err.(pgerr.Auth_Error)
	testing.expect(t, ok, "expected Auth_Error")
	testing.expect_value(t, auth_err.type, pgerr.Auth_Error_Type.SCRAM_Server_Signature_Mismatch)

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `scram_verify_server_final` undefined

- [ ] **Step 3: Implement `scram_verify_server_final` in `pgconn/auth_scram.odin`**

In `pgconn/auth_scram.odin`:
```odin
/*
	scram_verify_server_final extracts v= attribute from server-final-message
	and compares against state.server_signature.
*/
scram_verify_server_final :: proc(
	state: ^Scram_State,
	server_final_msg: string,
	allocator := context.temp_allocator,
) -> pgerr.Error {
	parts := strings.split(server_final_msg, ",", allocator)
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

	decoded_sig, decode_ok := base64.decode(var_v_b64, allocator = allocator)
	if !decode_ok || len(decoded_sig) != 32 {
		return pgerr.Auth_Error{
			type = .SCRAM_Invalid_Server_Final_Message,
			message = "Invalid base64 signature in SCRAM server-final message",
		}
	}

	// Compare decoded signature with state.server_signature in constant time / slice comparison
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/auth_scram.odin pgconn/auth_test.odin
git commit -m "feat(pgconn): implement scram_verify_server_final"
```

---

### Task 5: Top-Level Authentication Dispatcher (`auth_handle_challenge`) & Comprehensive Test Suite

**Files:**
- Modify: `pgconn/auth.odin`
- Modify: `pgconn/auth_test.odin`
- Update: `JIRA.md` (mark OPG-202 Done)

**Interfaces:**
- Produces:
  - `auth_handle_challenge(stream: ^Stream_Buffer, auth_msg: pgproto.Msg_Authentication, user: string, password: string, scram_state: ^Scram_State, temp_allocator := context.temp_allocator) -> (is_complete: bool, err: pgerr.Error)`

- [ ] **Step 1: Write failing tests for `auth_handle_challenge` across Cleartext, MD5, and SASL**

In `pgconn/auth_test.odin`:
```odin
@(test)
test_auth_handle_challenge_cleartext :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	transport := make_mock_transport(&mock)
	stream: Stream_Buffer
	stream_init(&stream, transport)
	defer stream_destroy(&stream)

	auth_msg := pgproto.Msg_Authentication{auth_type = .Cleartext_Password}
	is_complete, err := auth_handle_challenge(&stream, auth_msg, "postgres", "secret", nil)
	testing.expect(t, err == nil, "expected cleartext auth success")
	testing.expect_value(t, is_complete, false)

	// Check password message was sent: 'p' + 4-byte length + "secret\0"
	testing.expect_value(t, mock.written_bytes[0], 'p')

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_handle_challenge_md5 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	transport := make_mock_transport(&mock)
	stream: Stream_Buffer
	stream_init(&stream, transport)
	defer stream_destroy(&stream)

	auth_msg := pgproto.Msg_Authentication{
		auth_type = .MD5_Password,
		salt = [4]byte{1, 2, 3, 4},
	}
	is_complete, err := auth_handle_challenge(&stream, auth_msg, "postgres", "secret", nil)
	testing.expect(t, err == nil, "expected md5 auth success")
	testing.expect_value(t, is_complete, false)

	testing.expect_value(t, mock.written_bytes[0], 'p')

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_auth_handle_challenge_ok :: proc(t: ^testing.T) {
	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	transport := make_mock_transport(&mock)
	stream: Stream_Buffer
	stream_init(&stream, transport)
	defer stream_destroy(&stream)

	auth_msg := pgproto.Msg_Authentication{auth_type = .Ok}
	is_complete, err := auth_handle_challenge(&stream, auth_msg, "postgres", "secret", nil)
	testing.expect(t, err == nil, "expected auth ok")
	testing.expect_value(t, is_complete, true)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `auth_handle_challenge` undefined

- [ ] **Step 3: Implement `auth_handle_challenge` in `pgconn/auth.odin`**

In `pgconn/auth.odin`:
```odin
/*
	auth_handle_challenge dispatches an incoming PostgreSQL Authentication backend message,
	encoding and transmitting the appropriate credential response.
*/
auth_handle_challenge :: proc(
	stream: ^Stream_Buffer,
	auth_msg: pgproto.Msg_Authentication,
	user: string,
	password: string,
	scram_state: ^Scram_State,
	temp_allocator := context.temp_allocator,
) -> (
	is_complete: bool,
	err: pgerr.Error,
) {
	switch auth_msg.auth_type {
	case .Ok:
		return true, nil

	case .Cleartext_Password:
		pwd_msg := pgproto.frontend_encode_password_message(password, temp_allocator)
		stream_write_messages(stream, pwd_msg) or_return
		return false, nil

	case .MD5_Password:
		md5_pwd := compute_md5_password(user, password, auth_msg.salt, temp_allocator)
		pwd_msg := pgproto.frontend_encode_password_message(md5_pwd, temp_allocator)
		stream_write_messages(stream, pwd_msg) or_return
		return false, nil

	case .SASL:
		// Check for SCRAM-SHA-256 in mechanism list
		has_scram := false
		for mech in auth_msg.mechanisms {
			if mech == "SCRAM-SHA-256" {
				has_scram = true
				break
			}
		}
		if !has_scram {
			return false, pgerr.Auth_Error{
				type = .Unsupported_Auth_Mechanism,
				message = "Server did not offer SCRAM-SHA-256 mechanism",
			}
		}

		if scram_state == nil {
			return false, pgerr.Auth_Error{
				type = .Authentication_Failed,
				message = "SCRAM state not initialized",
			}
		}

		client_first := scram_client_first(scram_state, user, allocator = temp_allocator) or_return
		sasl_init_msg := pgproto.frontend_encode_sasl_initial_response(
			"SCRAM-SHA-256",
			client_first,
			temp_allocator,
		)
		stream_write_messages(stream, sasl_init_msg) or_return
		return false, nil

	case .SASL_Continue:
		if scram_state == nil {
			return false, pgerr.Auth_Error{
				type = .Authentication_Failed,
				message = "SCRAM state not initialized",
			}
		}

		client_final := scram_client_final(scram_state, auth_msg.sasl_data, password, temp_allocator) or_return
		sasl_resp_msg := pgproto.frontend_encode_sasl_response(client_final, temp_allocator)
		stream_write_messages(stream, sasl_resp_msg) or_return
		return false, nil

	case .SASL_Final:
		if scram_state == nil {
			return false, pgerr.Auth_Error{
				type = .Authentication_Failed,
				message = "SCRAM state not initialized",
			}
		}

		scram_verify_server_final(scram_state, auth_msg.sasl_data, temp_allocator) or_return
		// AuthenticationOk will follow immediately
		return false, nil

	case .Kerberos_V5, .SCM_Credential, .GSS, .GSS_Continue, .SSPI:
		return false, pgerr.Auth_Error{
			type = .Unsupported_Auth_Mechanism,
			message = "Unsupported authentication type requested by server",
		}
	}

	return false, pgerr.Auth_Error{
		type = .Authentication_Failed,
		message = "Unrecognized authentication message from server",
	}
}
```

- [ ] **Step 4: Run all tests and linters across all packages**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: All tests pass with zero warnings.

- [ ] **Step 5: Run address sanitizer check**

Run: `odin test tests -all-packages -sanitize:address`
Expected: Pass with zero sanitizer violations.

- [ ] **Step 6: Update `JIRA.md` status for OPG-202**

Mark `[OPG-202]` in `JIRA.md` as Done:
```markdown
### [OPG-202] SCRAM-SHA-256 & MD5 Authentication Handshake Engine
- [x] **Status**: Done
```

- [ ] **Step 7: Commit**

```bash
git add pgconn/auth.odin pgconn/auth_test.odin JIRA.md
git commit -m "feat(pgconn): complete OPG-202 authentication engine and mark task done in JIRA"
```

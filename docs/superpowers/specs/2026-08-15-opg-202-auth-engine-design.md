# Design Document: [OPG-202] SCRAM-SHA-256 & MD5 Authentication Handshake Engine

- **Date**: 2026-08-15
- **Task ID**: `OPG-202`
- **Layer**: `pgconn`
- **Package**: `package pgconn`
- **Files**:
  - `pgconn/auth.odin`
  - `pgconn/auth_scram.odin`
  - `pgconn/auth_test.odin`
- **Status**: Approved

---

## 1. Overview & Objectives

`OPG-202` implements pure-Odin PostgreSQL client authentication for Protocol 3.0:
1. **Cleartext Password Authentication**: Handles plain password responses.
2. **MD5 Authentication**: Computes `md5(md5(password + user) + salt)` using `core:crypto/legacy/md5` and `core:encoding/hex`.
3. **SCRAM-SHA-256 Authentication (RFC 5802 / RFC 7677)**:
   - Full client SASL handshake (`client-first-message` $\rightarrow$ `server-first-message` $\rightarrow$ `client-final-message` $\rightarrow$ `server-final-message` $\rightarrow$ `AuthenticationOk`).
   - Pure-Odin cryptographic primitives via `core:crypto/hash`, `core:crypto/hmac`, `core:crypto/pbkdf2`, and `core:encoding/base64`.
   - Deterministic client nonce injection for RFC 7677 golden vector testing.
4. **Zero Heap Leaks**: Transient parsing and message string generation use `context.temp_allocator`.
5. **Error Safety**: Returns structured `pgerr.Auth_Error` on mismatched signatures, malformed challenges, unsupported mechanisms, or invalid credentials.

---

## 2. Architecture & Data Structures

```odin
package pgconn

import "core:mem"
import "../pgerr"
import "../pgproto"

// Scram_State holds the conversation state across SCRAM-SHA-256 exchange rounds.
Scram_State :: struct {
	client_nonce:      string,
	combined_nonce:    string,
	salt:              []byte,
	iterations:        int,
	client_first_bare: string,
	server_first:      string,
	auth_message:      string,
	server_signature:  [32]byte,
	allocator:         mem.Allocator,
}
```

---

## 3. Procedural API Specification

### 3.1 MD5 Password Computation (`pgconn/auth.odin`)

```odin
// Computes PostgreSQL MD5 password hash: "md5" + hex(md5(hex(md5(password + user)) + salt))
compute_md5_password :: proc(
	user: string,
	password: string,
	salt: [4]byte,
	allocator := context.temp_allocator,
) -> string
```

#### Detailed Semantics:
1. Hash 1: `md5(password + user)` $\rightarrow$ 32-character lowercase hex string `h1`.
2. Hash 2: `md5(h1 + salt)` $\rightarrow$ 32-character lowercase hex string `h2`.
3. Return `"md5" + h2`.

### 3.2 SCRAM-SHA-256 Procedures (`pgconn/auth_scram.odin`)

```odin
// Initializes Scram_State and builds client-first-message.
// If injected_nonce is non-empty, it is used directly (for deterministic test vectors).
// Otherwise, generates 24 random bytes via crypto.rand_bytes and base64-encodes them.
scram_client_first :: proc(
	state: ^Scram_State,
	user: string,
	injected_nonce := "",
	allocator := context.temp_allocator,
) -> (
	client_first_msg: string,
	err: pgerr.Error,
)

// Parses server-first-message (extracts r=, s=, i=), derives keys via PBKDF2/HMAC,
// generates ClientProof, and builds client-final-message.
scram_client_final :: proc(
	state: ^Scram_State,
	server_first_msg: string,
	password: string,
	allocator := context.temp_allocator,
) -> (
	client_final_msg: string,
	err: pgerr.Error,
)

// Verifies server-final-message (v=) against ExpectedServerSignature.
scram_verify_server_final :: proc(
	state: ^Scram_State,
	server_final_msg: string,
	allocator := context.temp_allocator,
) -> pgerr.Error
```

#### Cryptographic Formulae:
- `client-first-message-bare` = `n=<user>,r=<client_nonce>` (where `user` is escaped per RFC 5802: `,` $\rightarrow$ `=2C`, `=` $\rightarrow$ `=3D`).
- `client-first-message` = `n,,` + `client-first-message-bare`.
- `server-first-message` = `r=<combined_nonce>,s=<salt_b64>,i=<iterations>`.
- `client-final-message-without-proof` = `c=biws,r=<combined_nonce>`.
- `auth-message` = `client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof`.
- `SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations)`.
- `ClientKey = HMAC-SHA256(SaltedPassword, "Client Key")`.
- `StoredKey = SHA256(ClientKey)`.
- `ClientSignature = HMAC-SHA256(StoredKey, auth-message)`.
- `ClientProof = ClientKey XOR ClientSignature`.
- `client-final-message` = `client-final-message-without-proof + ",p=" + base64(ClientProof)`.
- `ServerKey = HMAC-SHA256(SaltedPassword, "Server Key")`.
- `ExpectedServerSignature = HMAC-SHA256(ServerKey, auth-message)`.
- Server final message verification: extracts `v=<server_signature_b64>`, compares against `ExpectedServerSignature`.

### 3.3 Authentication Dispatcher (`pgconn/auth.odin`)

```odin
// Handles an incoming Authentication message from backend, performing the next step of auth.
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
)
```

---

## 4. Error Mapping Matrix

| Scenario | `pgerr.Auth_Error` Type |
|---|---|
| Unsupported auth mechanism (e.g. Kerberos, GSS) | `.Unsupported_Auth_Mechanism` |
| Malformed `server-first-message` (missing `r=`, `s=`, `i=`) | `.SCRAM_Invalid_Server_First_Message` |
| Malformed `server-final-message` (missing `v=`) | `.SCRAM_Invalid_Server_Final_Message` |
| `ServerSignature` does not match `ExpectedServerSignature` | `.SCRAM_Server_Signature_Mismatch` |
| Iteration count $\le 0$ or salt decode failure | `.SCRAM_Invalid_Server_First_Message` |

---

## 5. Verification & Test Plan (`pgconn/auth_test.odin`)

1. **RFC 7677 Official Test Vectors**:
   - Password: `"pencil"`
   - User: `"user"`
   - Client Nonce: `"rOprNGfwEbeRWgbNEkqO"`
   - Server First: `r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)h,s=QSXCR+Q6sek8bf92,i=4096`
   - Client Final Expected: `c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)h,p=dHzbZapWIclskip7gHG/vqafEmOXdMCgrEcuc9cmSmA=`
   - Server Final Expected: `v=6rriTRbeXPkWrfGt1QGoxi7hSUxiiuhZ7pwmgpYAcbU=`
2. **MD5 Known Vector Tests**:
   - Verified against known PostgreSQL MD5 test vectors.
3. **Cleartext Password Tests**:
   - Verification of `PasswordMessage` encoding.
4. **Malformed & Tampered Challenge Tests**:
   - Invalid Base64 salt.
   - Non-positive iteration count.
   - Missing fields in server messages.
   - Server signature mismatch / forged server signature.
5. **Memory Leak Tracking**:
   - All tests tracked with `core:mem.Tracking_Allocator`.
6. **Linters & Tooling**:
   - `odin test tests -all-packages -vet -strict-style`
   - `odin test tests -all-packages -sanitize:address`

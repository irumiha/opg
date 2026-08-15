package pgconn

import "core:crypto/legacy/md5"

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
	HEX_CHARS := "0123456789abcdef"

	// Stage 1: md5(password + user)
	var_ctx1: md5.Context
	md5.init(&var_ctx1)
	md5.update(&var_ctx1, transmute([]byte)password)
	md5.update(&var_ctx1, transmute([]byte)user)
	var_digest1: [16]byte
	md5.final(&var_ctx1, var_digest1[:])

	// Encode digest1 to lowercase hex
	hex_buf1: [32]byte
	for b, i in var_digest1 {
		hex_buf1[i * 2] = HEX_CHARS[b >> 4]
		hex_buf1[i * 2 + 1] = HEX_CHARS[b & 0x0F]
	}

	// Stage 2: md5(hex_buf1 + salt)
	local_salt := salt
	var_ctx2: md5.Context
	md5.init(&var_ctx2)
	md5.update(&var_ctx2, hex_buf1[:])
	md5.update(&var_ctx2, local_salt[:])
	var_digest2: [16]byte
	md5.final(&var_ctx2, var_digest2[:])

	// Stage 3: format "md5" + hex_buf2
	hex_buf2: [32]byte
	for b, i in var_digest2 {
		hex_buf2[i * 2] = HEX_CHARS[b >> 4]
		hex_buf2[i * 2 + 1] = HEX_CHARS[b & 0x0F]
	}

	out_bytes := make([]byte, 35, allocator)
	out_bytes[0] = 'm'
	out_bytes[1] = 'd'
	out_bytes[2] = '5'
	copy(out_bytes[3:], hex_buf2[:])

	return string(out_bytes)
}

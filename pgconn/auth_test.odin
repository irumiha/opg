package pgconn

import "core:mem"
import "core:testing"

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
	testing.expect_value(t, len(result), 35) // "md5" + 32 hex chars
	testing.expect(t, result[:3] == "md5", "expected md5 prefix")

	// Verify consistency across runs
	result2 := compute_md5_password("postgres", "password", salt, context.allocator)
	testing.expect_value(t, result, result2)

	delete(result, context.allocator)
	delete(result2, context.allocator)

	testing.expect_value(t, len(track.allocation_map), 0)
}

package pgerr

import "core:mem"
import "core:testing"

@(test)
test_postgres_error_clone_and_destroy :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	src := Postgres_Error{
		severity             = "ERROR",
		severity_unlocalized = "ERROR",
		code                 = "42P01",
		message              = "relation does not exist",
		hint                 = "check the table name",
	}

	cloned, err := postgres_error_clone(src, tracked)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, cloned.severity, "ERROR")
	testing.expect_value(t, cloned.severity_unlocalized, "ERROR")
	testing.expect_value(t, cloned.code, "42P01")
	testing.expect_value(t, cloned.message, "relation does not exist")
	testing.expect_value(t, cloned.hint, "check the table name")
	testing.expect_value(t, cloned.detail, "")

	// Cloned strings must not alias the source memory.
	testing.expect(t, raw_data(cloned.severity) != raw_data(src.severity), "severity must be a copy")
	testing.expect(t, raw_data(cloned.message) != raw_data(src.message), "message must be a copy")

	postgres_error_destroy(cloned, tracked)
	testing.expect_value(t, len(track.allocation_map), 0)
}

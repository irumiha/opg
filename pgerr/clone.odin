package pgerr

import "core:mem"
import "core:strings"

/*
	postgres_error_clone deep-copies every string field of a Postgres_Error into
	`allocator`. Parsed Postgres_Error values borrow from the network read buffer;
	clone anything that must outlive the next socket read.
	On allocation failure, already-cloned fields are freed via the deferred
	destroy below (no partial leak).
*/
postgres_error_clone :: proc(
	e: Postgres_Error,
	allocator := context.allocator,
) -> (
	res: Postgres_Error,
	err: mem.Allocator_Error,
) {
	defer if err != nil {
		postgres_error_destroy(res, allocator)
		res = Postgres_Error{}
	}
	res.severity = strings.clone(e.severity, allocator) or_return
	res.severity_unlocalized = strings.clone(e.severity_unlocalized, allocator) or_return
	res.code = strings.clone(e.code, allocator) or_return
	res.message = strings.clone(e.message, allocator) or_return
	res.detail = strings.clone(e.detail, allocator) or_return
	res.hint = strings.clone(e.hint, allocator) or_return
	res.position = strings.clone(e.position, allocator) or_return
	res.internal_position = strings.clone(e.internal_position, allocator) or_return
	res.internal_query = strings.clone(e.internal_query, allocator) or_return
	res.where_context = strings.clone(e.where_context, allocator) or_return
	res.schema_name = strings.clone(e.schema_name, allocator) or_return
	res.table_name = strings.clone(e.table_name, allocator) or_return
	res.column_name = strings.clone(e.column_name, allocator) or_return
	res.data_type_name = strings.clone(e.data_type_name, allocator) or_return
	res.constraint_name = strings.clone(e.constraint_name, allocator) or_return
	res.file = strings.clone(e.file, allocator) or_return
	res.line = strings.clone(e.line, allocator) or_return
	res.routine = strings.clone(e.routine, allocator) or_return
	return res, nil
}

/*
	postgres_error_destroy frees every string field previously cloned with
	postgres_error_clone using the same allocator.
*/
postgres_error_destroy :: proc(e: Postgres_Error, allocator := context.allocator) {
	delete(e.severity, allocator)
	delete(e.severity_unlocalized, allocator)
	delete(e.code, allocator)
	delete(e.message, allocator)
	delete(e.detail, allocator)
	delete(e.hint, allocator)
	delete(e.position, allocator)
	delete(e.internal_position, allocator)
	delete(e.internal_query, allocator)
	delete(e.where_context, allocator)
	delete(e.schema_name, allocator)
	delete(e.table_name, allocator)
	delete(e.column_name, allocator)
	delete(e.data_type_name, allocator)
	delete(e.constraint_name, allocator)
	delete(e.file, allocator)
	delete(e.line, allocator)
	delete(e.routine, allocator)
}

package pgconn

import "core:encoding/endian"
import "core:mem"
import "core:net"
import "core:testing"
import "core:time"
import "../pgerr"
import "../pgproto"

// Mock_Transport simulates network socket chunk delivery and capture for testing
Mock_Transport :: struct {
	read_chunks:       [dynamic][]byte,
	read_chunk_idx:    int,
	read_chunk_offset: int,
	written_bytes:     [dynamic]byte,
	simulate_eof:      bool,
	simulate_timeout:  bool,
	is_closed:         bool,
	read_timeout:      time.Duration,
	write_timeout:     time.Duration,
}

mock_transport_init :: proc(m: ^Mock_Transport, allocator := context.allocator) {
	m.read_chunks = make([dynamic][]byte, allocator)
	m.written_bytes = make([dynamic]byte, allocator)
}

mock_transport_destroy :: proc(m: ^Mock_Transport) {
	delete(m.read_chunks)
	delete(m.written_bytes)
}

mock_read :: proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error) {
	m := (^Mock_Transport)(transport)
	if m.is_closed {
		return 0, pgerr.Net_Error{type = .Socket_Closed}
	}
	if m.simulate_timeout {
		return 0, pgerr.Net_Error{type = .Timeout}
	}
	if m.simulate_eof || m.read_chunk_idx >= len(m.read_chunks) {
		return 0, pgerr.Net_Error{type = .Socket_Closed}
	}

	chunk := m.read_chunks[m.read_chunk_idx]
	remaining := chunk[m.read_chunk_offset:]
	to_copy := min(len(buf), len(remaining))
	copy(buf[:to_copy], remaining[:to_copy])
	m.read_chunk_offset += to_copy

	if m.read_chunk_offset >= len(chunk) {
		m.read_chunk_idx += 1
		m.read_chunk_offset = 0
	}

	return to_copy, nil
}

mock_write :: proc(transport: rawptr, data: []byte) -> (bytes_written: int, err: pgerr.Error) {
	m := (^Mock_Transport)(transport)
	if m.is_closed {
		return 0, pgerr.Net_Error{type = .Socket_Closed}
	}
	for b in data {
		append(&m.written_bytes, b)
	}
	return len(data), nil
}

mock_close :: proc(transport: rawptr) {
	m := (^Mock_Transport)(transport)
	m.is_closed = true
}

mock_set_deadlines :: proc(transport: rawptr, read_timeout, write_timeout: time.Duration) -> pgerr.Error {
	m := (^Mock_Transport)(transport)
	m.read_timeout = read_timeout
	m.write_timeout = write_timeout
	return nil
}

make_mock_transport :: proc(m: ^Mock_Transport) -> Stream_Transport {
	return Stream_Transport{
		data = m,
		read = mock_read,
		write = mock_write,
		close = mock_close,
		set_deadlines = mock_set_deadlines,
	}
}

@(test)
test_stream_mock_transport_read_write :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	append(&mock.read_chunks, []byte{1, 2, 3})
	append(&mock.read_chunks, []byte{4, 5})

	transport := make_mock_transport(&mock)

	buf: [4]byte
	n, err := transport.read(transport.data, buf[:])
	testing.expect(t, err == nil, "expected read success")
	testing.expect_value(t, n, 3)
	testing.expect_value(t, buf[0], 1)
	testing.expect_value(t, buf[1], 2)
	testing.expect_value(t, buf[2], 3)

	n2, err2 := transport.read(transport.data, buf[:])
	testing.expect(t, err2 == nil, "expected second read success")
	testing.expect_value(t, n2, 2)
	testing.expect_value(t, buf[0], 4)
	testing.expect_value(t, buf[1], 5)

	// Write test
	wn, werr := transport.write(transport.data, []byte{10, 20, 30})
	testing.expect(t, werr == nil, "expected write success")
	testing.expect_value(t, wn, 3)
	testing.expect_value(t, len(mock.written_bytes), 3)
	testing.expect_value(t, mock.written_bytes[0], 10)

	// Deadline test
	testing.expect(t, transport.set_deadlines != nil, "expected set_deadlines to be populated")
	derr := transport.set_deadlines(transport.data, 5 * time.Second, 10 * time.Second)
	testing.expect(t, derr == nil, "expected set_deadlines success")
	testing.expect_value(t, mock.read_timeout, 5 * time.Second)
	testing.expect_value(t, mock.write_timeout, 10 * time.Second)

	// Close test
	transport.close(transport.data)
	testing.expect(t, mock.is_closed, "expected mock closed")

	// Read/write on closed mock
	n_closed, rerr_closed := transport.read(transport.data, buf[:])
	testing.expect_value(t, n_closed, 0)
	net_err, is_net_err := rerr_closed.(pgerr.Net_Error)
	testing.expect(t, is_net_err, "expected Net_Error on closed read")
	testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Socket_Closed)

	wn_closed, werr_closed := transport.write(transport.data, []byte{1})
	testing.expect_value(t, wn_closed, 0)
	wnet_err, is_wnet_err := werr_closed.(pgerr.Net_Error)
	testing.expect(t, is_wnet_err, "expected Net_Error on closed write")
	testing.expect_value(t, wnet_err.type, pgerr.Net_Error_Type.Socket_Closed)

	mock_transport_destroy(&mock)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_mock_transport_edge_cases :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// Timeout simulation
	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		mock.simulate_timeout = true

		transport := make_mock_transport(&mock)
		buf: [4]byte
		n, err := transport.read(transport.data, buf[:])
		testing.expect_value(t, n, 0)
		net_err, ok := err.(pgerr.Net_Error)
		testing.expect(t, ok, "expected Net_Error on simulated timeout")
		testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Timeout)

		mock_transport_destroy(&mock)
	}

	// EOF simulation
	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		mock.simulate_eof = true

		transport := make_mock_transport(&mock)
		buf: [4]byte
		n, err := transport.read(transport.data, buf[:])
		testing.expect_value(t, n, 0)
		net_err, ok := err.(pgerr.Net_Error)
		testing.expect(t, ok, "expected Net_Error on simulated EOF")
		testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Socket_Closed)

		mock_transport_destroy(&mock)
	}

	// Partial read within single chunk
	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		append(&mock.read_chunks, []byte{1, 2, 3, 4, 5, 6})

		transport := make_mock_transport(&mock)
		buf: [2]byte
		n1, err1 := transport.read(transport.data, buf[:])
		testing.expect(t, err1 == nil)
		testing.expect_value(t, n1, 2)
		testing.expect_value(t, buf[0], 1)
		testing.expect_value(t, buf[1], 2)

		n2, err2 := transport.read(transport.data, buf[:])
		testing.expect(t, err2 == nil)
		testing.expect_value(t, n2, 2)
		testing.expect_value(t, buf[0], 3)
		testing.expect_value(t, buf[1], 4)

		n3, err3 := transport.read(transport.data, buf[:])
		testing.expect(t, err3 == nil)
		testing.expect_value(t, n3, 2)
		testing.expect_value(t, buf[0], 5)
		testing.expect_value(t, buf[1], 6)

		// Next read should be EOF / Socket_Closed
		n4, err4 := transport.read(transport.data, buf[:])
		testing.expect_value(t, n4, 0)
		net_err, ok := err4.(pgerr.Net_Error)
		testing.expect(t, ok)
		testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Socket_Closed)

		mock_transport_destroy(&mock)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_error_mappers :: proc(t: ^testing.T) {
	// Test map_recv_error
	testing.expect(t, map_recv_error(.None) == nil)

	r_to := map_recv_error(.Timeout).(pgerr.Net_Error)
	testing.expect_value(t, r_to.type, pgerr.Net_Error_Type.Timeout)

	r_wb := map_recv_error(.Would_Block).(pgerr.Net_Error)
	testing.expect_value(t, r_wb.type, pgerr.Net_Error_Type.Timeout)

	r_cc := map_recv_error(.Connection_Closed).(pgerr.Net_Error)
	testing.expect_value(t, r_cc.type, pgerr.Net_Error_Type.Socket_Closed)

	r_nc := map_recv_error(.Not_Connected).(pgerr.Net_Error)
	testing.expect_value(t, r_nc.type, pgerr.Net_Error_Type.Socket_Closed)

	r_nu := map_recv_error(.Network_Unreachable).(pgerr.Net_Error)
	testing.expect_value(t, r_nu.type, pgerr.Net_Error_Type.Host_Unreachable)

	r_ir := map_recv_error(.Insufficient_Resources).(pgerr.Net_Error)
	testing.expect_value(t, r_ir.type, pgerr.Net_Error_Type.Recv_Failed)

	r_ia := map_recv_error(.Invalid_Argument).(pgerr.Net_Error)
	testing.expect_value(t, r_ia.type, pgerr.Net_Error_Type.Recv_Failed)

	r_in := map_recv_error(.Interrupted).(pgerr.Net_Error)
	testing.expect_value(t, r_in.type, pgerr.Net_Error_Type.Recv_Failed)

	r_uk := map_recv_error(.Unknown).(pgerr.Net_Error)
	testing.expect_value(t, r_uk.type, pgerr.Net_Error_Type.Recv_Failed)

	// Test map_send_error
	testing.expect(t, map_send_error(.None) == nil)

	s_to := map_send_error(.Timeout).(pgerr.Net_Error)
	testing.expect_value(t, s_to.type, pgerr.Net_Error_Type.Timeout)

	s_wb := map_send_error(.Would_Block).(pgerr.Net_Error)
	testing.expect_value(t, s_wb.type, pgerr.Net_Error_Type.Timeout)

	s_cc := map_send_error(.Connection_Closed).(pgerr.Net_Error)
	testing.expect_value(t, s_cc.type, pgerr.Net_Error_Type.Socket_Closed)

	s_nc := map_send_error(.Not_Connected).(pgerr.Net_Error)
	testing.expect_value(t, s_nc.type, pgerr.Net_Error_Type.Socket_Closed)

	s_nu := map_send_error(.Network_Unreachable).(pgerr.Net_Error)
	testing.expect_value(t, s_nu.type, pgerr.Net_Error_Type.Host_Unreachable)

	s_hu := map_send_error(.Host_Unreachable).(pgerr.Net_Error)
	testing.expect_value(t, s_hu.type, pgerr.Net_Error_Type.Host_Unreachable)

	s_ir := map_send_error(.Insufficient_Resources).(pgerr.Net_Error)
	testing.expect_value(t, s_ir.type, pgerr.Net_Error_Type.Send_Failed)

	s_ia := map_send_error(.Invalid_Argument).(pgerr.Net_Error)
	testing.expect_value(t, s_ia.type, pgerr.Net_Error_Type.Send_Failed)

	s_in := map_send_error(.Interrupted).(pgerr.Net_Error)
	testing.expect_value(t, s_in.type, pgerr.Net_Error_Type.Send_Failed)

	s_uk := map_send_error(.Unknown).(pgerr.Net_Error)
	testing.expect_value(t, s_uk.type, pgerr.Net_Error_Type.Send_Failed)
}

@(test)
test_make_tcp_transport :: proc(t: ^testing.T) {
	tdata: TCP_Transport_Data
	dummy_socket := net.TCP_Socket(42)
	transport := make_tcp_transport(&tdata, dummy_socket)

	testing.expect(t, transport.data == &tdata, "expected transport.data to point to tdata")
	testing.expect_value(t, tdata.socket, dummy_socket)
	testing.expect(t, transport.read != nil, "expected transport.read to be populated")
	testing.expect(t, transport.write != nil, "expected transport.write to be populated")
	testing.expect(t, transport.close != nil, "expected transport.close to be populated")
	testing.expect(t, transport.set_deadlines != nil, "expected transport.set_deadlines to be populated")

	// Verify set_deadlines mutates TCP_Transport_Data
	derr := transport.set_deadlines(transport.data, 2 * time.Second, 4 * time.Second)
	testing.expect(t, derr == nil)
	testing.expect_value(t, tdata.read_timeout, 2 * time.Second)
	testing.expect_value(t, tdata.write_timeout, 4 * time.Second)
}

@(test)
test_stream_buffer_lifecycle_and_compaction :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)

	transport := make_mock_transport(&mock)

	stream: Stream_Buffer
	stream_init(&stream, transport, initial_capacity = 64, compact_threshold = 32)

	testing.expect_value(t, stream_unread_bytes(&stream), 0)

	// Simulate populating buffer with 40 bytes
	for i in 0 ..< 40 {
		stream.buf[i] = u8(i)
	}
	stream.write_offset = 40
	stream.read_offset = 35 // Consumed 35 bytes (>= compact_threshold of 32)

	testing.expect_value(t, stream_unread_bytes(&stream), 5)

	// Compact buffer
	stream_compact(&stream)

	testing.expect_value(t, stream.read_offset, 0)
	testing.expect_value(t, stream.write_offset, 5)
	testing.expect_value(t, stream_unread_bytes(&stream), 5)
	for i in 0 ..< 5 {
		testing.expect_value(t, stream.buf[i], u8(35 + i))
	}

	stream_close(&stream)
	testing.expect(t, mock.is_closed, "stream_close should close underlying transport")

	// Nil safety checks
	stream_destroy(nil)
	stream_close(nil)

	// Compact when read_offset == 0 (no-op)
	stream_compact(&stream)
	testing.expect_value(t, stream.read_offset, 0)
	testing.expect_value(t, stream.write_offset, 5)

	// Compact when unread == 0
	stream.read_offset = 5
	stream_compact(&stream)
	testing.expect_value(t, stream.read_offset, 0)
	testing.expect_value(t, stream.write_offset, 0)

	stream_destroy(&stream)
	mock_transport_destroy(&mock)

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_single_message :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		// Build ReadyForQuery message: 'Z', length 5, 'I' (Idle) -> [ 'Z', 0, 0, 0, 5, 'I' ]
		rfq_bytes := []byte{'Z', 0, 0, 0, 5, 'I'}
		append(&mock.read_chunks, rfq_bytes)

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		msg, err := stream_read_message(&stream)
		testing.expect(t, err == nil, "expected successful message parse")

		rfq, ok := msg.(pgproto.Msg_Ready_For_Query)
		testing.expect(t, ok, "expected ReadyForQuery message type")
		testing.expect_value(t, rfq.status, pgproto.Transaction_Status.Idle)
		testing.expect_value(t, stream_unread_bytes(&stream), 0)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_fragmented_message :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		// Split 6-byte message across 3 chunks: [ 'Z', 0 ], [ 0, 0 ], [ 5, 'I' ]
		append(&mock.read_chunks, []byte{'Z', 0})
		append(&mock.read_chunks, []byte{0, 0})
		append(&mock.read_chunks, []byte{5, 'I'})

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		msg, err := stream_read_message(&stream)
		testing.expect(t, err == nil, "expected successful fragmented message parse")

		rfq, ok := msg.(pgproto.Msg_Ready_For_Query)
		testing.expect(t, ok, "expected ReadyForQuery message type")
		testing.expect_value(t, rfq.status, pgproto.Transaction_Status.Idle)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_multiple_messages_in_single_chunk :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		// Combine ReadyForQuery ('Z') and ParseComplete ('1') in one chunk
		combined := []byte{
			'Z', 0, 0, 0, 5, 'I',
			'1', 0, 0, 0, 4,
		}
		append(&mock.read_chunks, combined)

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		// Read msg 1
		msg1, err1 := stream_read_message(&stream)
		testing.expect(t, err1 == nil, "expected msg1 success")
		_, ok1 := msg1.(pgproto.Msg_Ready_For_Query)
		testing.expect(t, ok1, "expected ReadyForQuery")

		// Read msg 2
		msg2, err2 := stream_read_message(&stream)
		testing.expect(t, err2 == nil, "expected msg2 success")
		_, ok2 := msg2.(pgproto.Msg_Parse_Complete)
		testing.expect(t, ok2, "expected ParseComplete")

		testing.expect_value(t, stream_unread_bytes(&stream), 0)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_invalid_length :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		// Invalid length header: length = 2 (< 4)
		invalid_bytes := []byte{'Z', 0, 0, 0, 2}
		append(&mock.read_chunks, invalid_bytes)

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		_, err := stream_read_message(&stream)
		testing.expect(t, err != nil, "expected error for invalid length header")
		proto_err, ok := err.(pgerr.Protocol_Error)
		testing.expect(t, ok, "expected Protocol_Error")
		testing.expect_value(t, proto_err.type, pgerr.Protocol_Error_Type.Invalid_Length)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_transport_error_and_closed :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	// Test transport timeout error
	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)
		mock.simulate_timeout = true

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		_, err := stream_read_message(&stream)
		testing.expect(t, err != nil, "expected error on timeout")
		net_err, ok := err.(pgerr.Net_Error)
		testing.expect(t, ok, "expected Net_Error")
		testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Timeout)
	}

	// Test EOF / Socket closed when reading header
	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)
		mock.simulate_eof = true

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		_, err := stream_read_message(&stream)
		testing.expect(t, err != nil, "expected error on eof")
		net_err, ok := err.(pgerr.Net_Error)
		testing.expect(t, ok, "expected Net_Error")
		testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Socket_Closed)
	}

	// Test EOF / Socket closed mid-packet
	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)
		// Only header arrives, then EOF
		append(&mock.read_chunks, []byte{'Z', 0, 0, 0, 5})
		mock.simulate_eof = false

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		// First read gets 5 bytes, then next read sees EOF because no more chunks
		_, err := stream_read_message(&stream)
		testing.expect(t, err != nil, "expected error on truncated packet eof")
		net_err, ok := err.(pgerr.Net_Error)
		testing.expect(t, ok, "expected Net_Error")
		testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Socket_Closed)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_large_message_buffer_growth_and_compaction :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		// Message with total length 15: CommandComplete ('C'), payload len 14
		cc_tag := "SELECT 42\x00"
		cc_bytes := make([]byte, 1 + 4 + len(cc_tag))
		defer delete(cc_bytes)
		cc_bytes[0] = 'C'
		cc_len := u32(4 + len(cc_tag))
		cc_bytes[1] = byte(cc_len >> 24)
		cc_bytes[2] = byte(cc_len >> 16)
		cc_bytes[3] = byte(cc_len >> 8)
		cc_bytes[4] = byte(cc_len)
		copy(cc_bytes[5:], cc_tag)

		// Fragment into tiny chunks of 3 bytes each
		chunk_size :: 3
		for i := 0; i < len(cc_bytes); i += chunk_size {
			end := min(i + chunk_size, len(cc_bytes))
			append(&mock.read_chunks, cc_bytes[i:end])
		}

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		// Initialize with tiny capacity 8 and low compaction threshold 4 to force growth & compaction
		stream_init(&stream, transport, initial_capacity = 8, compact_threshold = 4)
		defer stream_destroy(&stream)

		msg, err := stream_read_message(&stream)
		testing.expect(t, err == nil, "expected successful message parse after buffer growth")
		cc, ok := msg.(pgproto.Msg_Command_Complete)
		testing.expect(t, ok, "expected Msg_Command_Complete")
		testing.expect_value(t, cc.tag, "SELECT 42")
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_parse_error :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		// Unknown backend message type '?'
		bad_bytes := []byte{'?', 0, 0, 0, 4}
		append(&mock.read_chunks, bad_bytes)

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		_, err := stream_read_message(&stream)
		testing.expect(t, err != nil, "expected error on unknown message type")
		proto_err, ok := err.(pgerr.Protocol_Error)
		testing.expect(t, ok, "expected Protocol_Error")
		testing.expect_value(t, proto_err.type, pgerr.Protocol_Error_Type.Unknown_Message_Type)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_borrowed_string_validity_with_compaction :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		// Msg 1: CommandComplete: 'C', len 15, "SELECT 42\x00" -> total 15 bytes
		cc_tag := "SELECT 42\x00"
		cc_bytes := make([]byte, 1 + 4 + len(cc_tag))
		defer delete(cc_bytes)
		cc_bytes[0] = 'C'
		cc_len := u32(4 + len(cc_tag))
		cc_bytes[1] = byte(cc_len >> 24)
		cc_bytes[2] = byte(cc_len >> 16)
		cc_bytes[3] = byte(cc_len >> 8)
		cc_bytes[4] = byte(cc_len)
		copy(cc_bytes[5:], cc_tag)

		// Msg 2: ReadyForQuery: 'Z', len 5, 'I' -> total 6 bytes
		rfq_bytes := []byte{'Z', 0, 0, 0, 5, 'I'}

		// Append both messages in chunks
		append(&mock.read_chunks, cc_bytes)
		append(&mock.read_chunks, rfq_bytes)

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		// Set compact_threshold = 10 (smaller than Msg 1 length of 15 bytes)
		stream_init(&stream, transport, initial_capacity = 64, compact_threshold = 10)
		defer stream_destroy(&stream)

		// 1. Read first message
		msg1, err1 := stream_read_message(&stream)
		testing.expect(t, err1 == nil, "expected msg1 success")
		cc, ok1 := msg1.(pgproto.Msg_Command_Complete)
		testing.expect(t, ok1, "expected Msg_Command_Complete")

		// Verify read_offset >= compact_threshold (15 >= 10)
		testing.expect_value(t, stream.read_offset, 15)

		// Crucial assertion: cc.tag borrowed string view is intact and points to "SELECT 42"
		// without being overwritten or shifted prematurely
		testing.expect_value(t, cc.tag, "SELECT 42")

		// 2. Read second message: compaction should trigger at the start of stream_read_message
		msg2, err2 := stream_read_message(&stream)
		testing.expect(t, err2 == nil, "expected msg2 success")
		rfq, ok2 := msg2.(pgproto.Msg_Ready_For_Query)
		testing.expect(t, ok2, "expected Msg_Ready_For_Query")
		testing.expect_value(t, rfq.status, pgproto.Transaction_Status.Idle)
		testing.expect_value(t, stream_unread_bytes(&stream), 0)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_write_messages_pipelined :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		msg1 := []byte{'P', 0, 0, 0, 4}
		msg2 := []byte{'B', 0, 0, 0, 4}
		msg3 := []byte{'S', 0, 0, 0, 4}

		err := stream_write_messages(&stream, msg1, msg2, msg3)
		testing.expect(t, err == nil, "expected successful write of pipelined messages")
		testing.expect_value(t, len(mock.written_bytes), 15)
		testing.expect_value(t, mock.written_bytes[0], 'P')
		testing.expect_value(t, mock.written_bytes[5], 'B')
		testing.expect_value(t, mock.written_bytes[10], 'S')

		// Test writing with empty slices (should skip without error)
		err_empty := stream_write_messages(&stream, []byte{})
		testing.expect(t, err_empty == nil, "expected empty message write to succeed")
		testing.expect_value(t, len(mock.written_bytes), 15)

		// Test nil stream or nil transport.write
		err_nil := stream_write_messages(nil, msg1)
		testing.expect(t, err_nil != nil, "expected error on nil stream")
		net_err, is_net := err_nil.(pgerr.Net_Error)
		testing.expect(t, is_net)
		testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Socket_Closed)

		stream_no_write: Stream_Buffer
		err_no_write := stream_write_messages(&stream_no_write, msg1)
		testing.expect(t, err_no_write != nil, "expected error on nil transport.write")

		// Test transport write error (e.g., closed transport)
		mock.is_closed = true
		err_closed := stream_write_messages(&stream, msg1)
		testing.expect(t, err_closed != nil, "expected error on closed transport write")
		closed_net_err, is_closed_net := err_closed.(pgerr.Net_Error)
		testing.expect(t, is_closed_net)
		testing.expect_value(t, closed_net_err.type, pgerr.Net_Error_Type.Socket_Closed)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_timeout_error :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		mock.simulate_timeout = true
		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		_, err := stream_read_message(&stream)
		net_err, ok := err.(pgerr.Net_Error)
		testing.expect(t, ok, "expected Net_Error")
		testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Timeout)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_eof_closed_error :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		mock.simulate_eof = true
		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		_, err := stream_read_message(&stream)
		net_err, ok := err.(pgerr.Net_Error)
		testing.expect(t, ok, "expected Net_Error")
		testing.expect_value(t, net_err.type, pgerr.Net_Error_Type.Socket_Closed)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_invalid_length_error :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		// Header with length 2 (< 4 minimum)
		append(&mock.read_chunks, []byte{'Z', 0, 0, 0, 2})
		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		stream_init(&stream, transport)
		defer stream_destroy(&stream)

		_, err := stream_read_message(&stream)
		proto_err, ok := err.(pgerr.Protocol_Error)
		testing.expect(t, ok, "expected Protocol_Error")
		testing.expect_value(t, proto_err.type, pgerr.Protocol_Error_Type.Invalid_Length)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_large_packet_buffer_expansion :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	{
		mock: Mock_Transport
		mock_transport_init(&mock)
		defer mock_transport_destroy(&mock)

		// Create a large CommandComplete message: 'C', length 4 + 5000 bytes string + 1 null byte
		large_payload := make([]byte, 5000, context.temp_allocator)
		for i in 0 ..< 5000 {
			large_payload[i] = 'A'
		}

		builder := make([dynamic]byte, context.temp_allocator)
		append(&builder, 'C')
		len_pos := len(builder)
		append(&builder, 0, 0, 0, 0)
		append(&builder, ..large_payload)
		append(&builder, 0)
		total_len := i32(len(builder) - 1)
		endian.put_i32(builder[len_pos : len_pos + 4], .Big, total_len)

		append(&mock.read_chunks, builder[:])

		transport := make_mock_transport(&mock)
		stream: Stream_Buffer
		// Initialize with small initial capacity (128) to test dynamic expansion
		stream_init(&stream, transport, initial_capacity = 128)
		defer stream_destroy(&stream)

		msg, err := stream_read_message(&stream)
		testing.expect(t, err == nil, "expected successful parse of large message")
		cc, ok := msg.(pgproto.Msg_Command_Complete)
		testing.expect(t, ok, "expected CommandComplete")
		testing.expect_value(t, len(cc.tag), 5000)
	}

	testing.expect_value(t, len(track.allocation_map), 0)
}




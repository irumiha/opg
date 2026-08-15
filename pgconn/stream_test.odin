package pgconn

import "core:mem"
import "core:net"
import "core:testing"
import "core:time"
import "../pgerr"

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


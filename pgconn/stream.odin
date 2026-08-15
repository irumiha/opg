package pgconn

import "core:encoding/endian"
import "core:mem"
import "core:net"
import "core:time"
import "../pgerr"
import "../pgproto"

// Stream_Transport provides polymorphic I/O over TCP sockets or dynamic TLS streams.
Stream_Transport :: struct {
	data:          rawptr,
	read:          proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error),
	write:         proc(transport: rawptr, data: []byte) -> (bytes_written: int, err: pgerr.Error),
	close:         proc(transport: rawptr),
	set_deadlines: proc(transport: rawptr, read_timeout, write_timeout: time.Duration) -> pgerr.Error,
}

// TCP_Transport_Data is the concrete state for plain TCP socket communication.
TCP_Transport_Data :: struct {
	socket:        net.TCP_Socket,
	read_timeout:  time.Duration,
	write_timeout: time.Duration,
}

map_recv_error :: proc(err: net.TCP_Recv_Error) -> pgerr.Error {
	switch err {
	case .None:
		return nil
	case .Timeout, .Would_Block:
		return pgerr.Net_Error{type = .Timeout, raw_net_error = err}
	case .Connection_Closed, .Not_Connected:
		return pgerr.Net_Error{type = .Socket_Closed, raw_net_error = err}
	case .Network_Unreachable:
		return pgerr.Net_Error{type = .Host_Unreachable, raw_net_error = err}
	case .Insufficient_Resources, .Invalid_Argument, .Interrupted, .Unknown:
		return pgerr.Net_Error{type = .Recv_Failed, raw_net_error = err}
	}
	return pgerr.Net_Error{type = .Recv_Failed, raw_net_error = err}
}

map_send_error :: proc(err: net.TCP_Send_Error) -> pgerr.Error {
	switch err {
	case .None:
		return nil
	case .Timeout, .Would_Block:
		return pgerr.Net_Error{type = .Timeout, raw_net_error = err}
	case .Connection_Closed, .Not_Connected:
		return pgerr.Net_Error{type = .Socket_Closed, raw_net_error = err}
	case .Network_Unreachable, .Host_Unreachable:
		return pgerr.Net_Error{type = .Host_Unreachable, raw_net_error = err}
	case .Insufficient_Resources, .Invalid_Argument, .Interrupted, .Unknown:
		return pgerr.Net_Error{type = .Send_Failed, raw_net_error = err}
	}
	return pgerr.Net_Error{type = .Send_Failed, raw_net_error = err}
}

tcp_read :: proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error) {
	data := (^TCP_Transport_Data)(transport)
	n, rerr := net.recv_tcp(data.socket, buf)
	if rerr != .None {
		return 0, map_recv_error(rerr)
	}
	if n == 0 {
		return 0, pgerr.Net_Error{type = .Socket_Closed}
	}
	return n, nil
}

tcp_write :: proc(transport: rawptr, data: []byte) -> (bytes_written: int, err: pgerr.Error) {
	tdata := (^TCP_Transport_Data)(transport)
	total_written := 0
	for total_written < len(data) {
		n, serr := net.send_tcp(tdata.socket, data[total_written:])
		if serr != .None {
			return total_written, map_send_error(serr)
		}
		total_written += n
	}
	return total_written, nil
}

tcp_close :: proc(transport: rawptr) {
	data := (^TCP_Transport_Data)(transport)
	net.close(data.socket)
}

tcp_set_deadlines :: proc(transport: rawptr, read_timeout, write_timeout: time.Duration) -> pgerr.Error {
	data := (^TCP_Transport_Data)(transport)
	data.read_timeout = read_timeout
	data.write_timeout = write_timeout
	// Note: core:net socket timeout configuration can be hooked here
	return nil
}

make_tcp_transport :: proc(data: ^TCP_Transport_Data, socket: net.TCP_Socket) -> Stream_Transport {
	data.socket = socket
	return Stream_Transport{
		data = data,
		read = tcp_read,
		write = tcp_write,
		close = tcp_close,
		set_deadlines = tcp_set_deadlines,
	}
}

// Stream_Buffer accumulates incoming bytes and manages outbound writes.
Stream_Buffer :: struct {
	transport:         Stream_Transport,
	buf:               [dynamic]byte,
	read_offset:       int,
	write_offset:      int,
	allocator:         mem.Allocator,
	compact_threshold: int,
}

stream_init :: proc(
	s: ^Stream_Buffer,
	transport: Stream_Transport,
	initial_capacity := 8192,
	compact_threshold := 4096,
	allocator := context.allocator,
) {
	s.transport = transport
	s.allocator = allocator
	s.buf = make([dynamic]byte, initial_capacity, allocator)
	s.read_offset = 0
	s.write_offset = 0
	s.compact_threshold = compact_threshold
}

stream_destroy :: proc(s: ^Stream_Buffer) {
	if s == nil do return
	delete(s.buf)
	s.buf = nil
	s.read_offset = 0
	s.write_offset = 0
}

stream_close :: proc(s: ^Stream_Buffer) {
	if s == nil do return
	if s.transport.close != nil {
		s.transport.close(s.transport.data)
	}
}

stream_unread_bytes :: proc(s: ^Stream_Buffer) -> int {
	return s.write_offset - s.read_offset
}

stream_compact :: proc(s: ^Stream_Buffer) {
	if s.read_offset == 0 do return

	unread := s.write_offset - s.read_offset
	if unread > 0 {
		copy(s.buf[0:unread], s.buf[s.read_offset:s.write_offset])
	}
	s.read_offset = 0
	s.write_offset = unread
}

stream_read_message :: proc(
	s: ^Stream_Buffer,
	temp_allocator := context.temp_allocator,
) -> (
	msg: pgproto.Backend_Message,
	err: pgerr.Error,
) {
	// Compact at entry if read_offset exceeded threshold from previous reads
	if s.read_offset >= s.compact_threshold {
		stream_compact(s)
	}

	for {
		// 1. Check if we have at least 5 bytes for packet header (1 byte type + 4 bytes length)
		unread := s.write_offset - s.read_offset
		if unread >= 5 {
			len_bytes := s.buf[s.read_offset + 1 : s.read_offset + 5]
			payload_len, ok := endian.get_i32(len_bytes, .Big)
			if !ok || payload_len < 4 {
				return nil, pgerr.Protocol_Error{
					type = .Invalid_Length,
					message = "Invalid message length header",
					byte_offset = s.read_offset + 1,
				}
			}

			total_packet_len := 1 + int(payload_len)

			// 2. If entire packet is in buffer, parse and return
			if unread >= total_packet_len {
				packet_slice := s.buf[s.read_offset : s.read_offset + total_packet_len]
				parsed_msg, _, parse_err := pgproto.parse_message(packet_slice, temp_allocator)
				if parse_err != nil {
					return nil, parse_err
				}

				s.read_offset += total_packet_len

				return parsed_msg, nil
			}

			// Need more bytes: ensure buffer has enough capacity for total_packet_len
			required_capacity := s.read_offset + total_packet_len
			if required_capacity > len(s.buf) {
				// If compacting would make room, compact first
				if s.read_offset > 0 {
					stream_compact(s)
				}
				required_capacity = s.write_offset + (total_packet_len - (s.write_offset - s.read_offset))
				if required_capacity > len(s.buf) {
					resize(&s.buf, max(len(s.buf) * 2, required_capacity))
				}
			}
		} else {
			// Ensure buffer has space to read more bytes
			if s.write_offset >= len(s.buf) {
				if s.read_offset > 0 {
					stream_compact(s)
				}
				if s.write_offset >= len(s.buf) {
					resize(&s.buf, len(s.buf) * 2)
				}
			}
		}

		// 3. Read available bytes from transport
		dest := s.buf[s.write_offset:]
		n, rerr := s.transport.read(s.transport.data, dest)
		if rerr != nil {
			return nil, rerr
		}
		if n == 0 {
			return nil, pgerr.Net_Error{type = .Socket_Closed}
		}
		s.write_offset += n
	}
}



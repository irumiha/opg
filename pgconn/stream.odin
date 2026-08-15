package pgconn

import "core:net"
import "core:time"
import "../pgerr"

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

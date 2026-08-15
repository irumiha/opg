# [OPG-201] TCP Socket Stream Buffering & Message Accumulator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the network transport abstraction and dynamic message accumulator (`pgconn/stream.odin`) to handle TCP fragmentation, packet framing, and multi-packet message streams for PostgreSQL Protocol 3.0 backend messages.

**Architecture:** A polymorphic `Stream_Transport` struct provides procedural virtual table operations (`read`, `write`, `close`, `set_deadlines`) wrapping `core:net.TCP_Socket` (and ready for dynamic TLS in OPG-205). `Stream_Buffer` accumulates incoming bytes until complete PostgreSQL 3.0 packets (`1-byte type + 4-byte length`) arrive, bridging directly to `pgproto.parse_message` with `context.temp_allocator`.

**Tech Stack:** Odin, `core:net`, `core:mem`, `core:time`, `core:encoding/endian`, `pgproto`, `pgerr`.

**Spec:** [`docs/superpowers/specs/2026-08-15-opg-201-stream-buffer-design.md`](file:///home/igorrumiha/Projects/odin-projects/opg/docs/superpowers/specs/2026-08-15-opg-201-stream-buffer-design.md)

## Global Constraints

- Never do what was not specifically asked for.
- All errors must return `pgerr.Error` (tagged union). Subpackages import `pgerr` — never `root.odin`.
- All transient packet parsing uses `allocator := context.temp_allocator`.
- Multi-byte integers must be read/written in Network Byte Order (Big-Endian) using `core:encoding/endian` or `pgproto`.
- Unit tests must be 100% network-independent using `Mock_Transport`.
- Zero memory leaks verified using `core:mem.Tracking_Allocator`.

---

### Task 1: `Stream_Transport` Interface, `TCP_Transport_Data` & `Mock_Transport`

**Files:**
- Create: `pgconn/stream.odin`
- Create: `pgconn/stream_test.odin`

**Interfaces:**
- Produces:
  - `Stream_Transport :: struct`
  - `TCP_Transport_Data :: struct`
  - `make_tcp_transport(data: ^TCP_Transport_Data, socket: net.TCP_Socket) -> Stream_Transport`
  - `map_recv_error(err: net.TCP_Recv_Error) -> pgerr.Error`
  - `map_send_error(err: net.TCP_Send_Error) -> pgerr.Error`
  - `Mock_Transport :: struct` (for unit tests)

- [ ] **Step 1: Write failing tests for `Stream_Transport` and `Mock_Transport`**

In `pgconn/stream_test.odin`:
```odin
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
	defer mock_transport_destroy(&mock)

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

	// Close test
	transport.close(transport.data)
	testing.expect(t, mock.is_closed, "expected mock closed")

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `Stream_Transport` undefined

- [ ] **Step 3: Implement `Stream_Transport`, `TCP_Transport_Data`, and error mappers**

In `pgconn/stream.odin`:
```odin
package pgconn

import "core:mem"
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/stream.odin pgconn/stream_test.odin
git commit -m "feat(pgconn): add Stream_Transport interface and TCP transport implementation"
```

---

### Task 2: `Stream_Buffer` Lifecycle & Buffer Compaction

**Files:**
- Modify: `pgconn/stream.odin`
- Modify: `pgconn/stream_test.odin`

**Interfaces:**
- Produces:
  - `Stream_Buffer :: struct`
  - `stream_init(s: ^Stream_Buffer, transport: Stream_Transport, initial_capacity := 8192, compact_threshold := 4096, allocator := context.allocator)`
  - `stream_destroy(s: ^Stream_Buffer)`
  - `stream_close(s: ^Stream_Buffer)`
  - `stream_compact(s: ^Stream_Buffer)`
  - `stream_unread_bytes(s: ^Stream_Buffer) -> int`

- [ ] **Step 1: Write failing test for `Stream_Buffer` lifecycle & compaction**

In `pgconn/stream_test.odin`:
```odin
@(test)
test_stream_buffer_lifecycle_and_compaction :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	mock: Mock_Transport
	mock_transport_init(&mock)
	defer mock_transport_destroy(&mock)

	transport := make_mock_transport(&mock)

	stream: Stream_Buffer
	stream_init(&stream, transport, initial_capacity = 64, compact_threshold = 32)
	defer stream_destroy(&stream)

	testing.expect_value(t, stream_unread_bytes(&stream), 0)

	// Simulate populating buffer with 40 bytes
	for i in 0 ..< 40 {
		append(&stream.buf, u8(i))
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

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `Stream_Buffer` undefined

- [ ] **Step 3: Implement `Stream_Buffer` and lifecycle procedures**

In `pgconn/stream.odin`:
```odin
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/stream.odin pgconn/stream_test.odin
git commit -m "feat(pgconn): add Stream_Buffer lifecycle and compaction"
```

---

### Task 3: Packet Framing & Message Reading (`stream_read_message`)

**Files:**
- Modify: `pgconn/stream.odin`
- Modify: `pgconn/stream_test.odin`

**Interfaces:**
- Produces:
  - `stream_read_message(s: ^Stream_Buffer, temp_allocator := context.temp_allocator) -> (msg: pgproto.Backend_Message, err: pgerr.Error)`

- [ ] **Step 1: Write failing tests for packet framing & fragmented message reads**

In `pgconn/stream_test.odin`:
```odin
import "../pgproto"

@(test)
test_stream_read_single_message :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

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

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_fragmented_message :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

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

	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
test_stream_read_multiple_messages_in_single_chunk :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

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
	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `stream_read_message` undefined

- [ ] **Step 3: Implement `stream_read_message`**

In `pgconn/stream.odin`:
```odin
import "core:encoding/endian"
import "../pgproto"

stream_read_message :: proc(
	s: ^Stream_Buffer,
	temp_allocator := context.temp_allocator,
) -> (
	msg: pgproto.Backend_Message,
	err: pgerr.Error,
) {
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

				// Check compaction threshold
				if s.read_offset >= s.compact_threshold {
					stream_compact(s)
				}

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pgconn/stream.odin pgconn/stream_test.odin
git commit -m "feat(pgconn): implement packet framing and stream_read_message"
```

---

### Task 4: Outbound Message Writing & Pipelined Multi-Write

**Files:**
- Modify: `pgconn/stream.odin`
- Modify: `pgconn/stream_test.odin`

**Interfaces:**
- Produces:
  - `stream_write_messages(s: ^Stream_Buffer, msgs: ..[]byte) -> (err: pgerr.Error)`

- [ ] **Step 1: Write failing test for `stream_write_messages`**

In `pgconn/stream_test.odin`:
```odin
@(test)
test_stream_write_messages_pipelined :: proc(t: ^testing.T) {
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

	msg1 := []byte{'P', 0, 0, 0, 4}
	msg2 := []byte{'B', 0, 0, 0, 4}
	msg3 := []byte{'S', 0, 0, 0, 4}

	err := stream_write_messages(&stream, msg1, msg2, msg3)
	testing.expect(t, err == nil, "expected successful write of pipelined messages")
	testing.expect_value(t, len(mock.written_bytes), 15)
	testing.expect_value(t, mock.written_bytes[0], 'P')
	testing.expect_value(t, mock.written_bytes[5], 'B')
	testing.expect_value(t, mock.written_bytes[10], 'S')

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `odin test tests -all-packages`
Expected: FAIL with `stream_write_messages` undefined

- [ ] **Step 3: Implement `stream_write_messages`**

In `pgconn/stream.odin`:
```odin
stream_write_messages :: proc(
	s: ^Stream_Buffer,
	msgs: ..[]byte,
) -> (
	err: pgerr.Error,
) {
	if s == nil || s.transport.write == nil {
		return pgerr.Net_Error{type = .Socket_Closed}
	}

	for msg in msgs {
		if len(msg) == 0 do continue
		_, werr := s.transport.write(s.transport.data, msg)
		if werr != nil {
			return werr
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
git add pgconn/stream.odin pgconn/stream_test.odin
git commit -m "feat(pgconn): implement stream_write_messages"
```

---

### Task 5: Comprehensive Error Handling, Edge Cases & Verification Suite

**Files:**
- Modify: `pgconn/stream_test.odin`
- Update: `JIRA.md` (mark OPG-201 Done)

**Interfaces:**
- Test coverage for all error branches: EOF, timeouts, write errors, invalid length headers, corrupted packets, huge packets requiring buffer growth.

- [ ] **Step 1: Add unit tests for all error and edge case paths**

In `pgconn/stream_test.odin`:
```odin
@(test)
test_stream_read_timeout_error :: proc(t: ^testing.T) {
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

@(test)
test_stream_read_eof_closed_error :: proc(t: ^testing.T) {
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

@(test)
test_stream_read_invalid_length_error :: proc(t: ^testing.T) {
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

@(test)
test_stream_large_packet_buffer_expansion :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

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

	testing.expect_value(t, len(track.allocation_map), 0)
}
```

- [ ] **Step 2: Run all tests and linters across all packages**

Run: `odin test tests -all-packages -vet -strict-style`
Expected: All tests pass with zero warnings.

- [ ] **Step 3: Run address sanitizer check**

Run: `odin test tests -all-packages -sanitize:address`
Expected: Pass with zero sanitizer violations.

- [ ] **Step 4: Update `JIRA.md` status for OPG-201**

Mark `[OPG-201]` in `JIRA.md` as Done:
```markdown
### [OPG-201] TCP Socket Stream Buffering & Message Accumulator
- [x] **Status**: Done
```

- [ ] **Step 5: Commit**

```bash
git add pgconn/stream_test.odin JIRA.md
git commit -m "feat(pgconn): complete OPG-201 test suite and mark task done in JIRA"
```

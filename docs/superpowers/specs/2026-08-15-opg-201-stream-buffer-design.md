# Design Document: [OPG-201] TCP Socket Stream Buffering & Message Accumulator

- **Date**: 2026-08-15
- **Task ID**: `OPG-201`
- **Layer**: `pgconn`
- **Package**: `package pgconn`
- **Files**:
  - `pgconn/stream.odin`
  - `pgconn/stream_test.odin`
- **Status**: Approved

---

## 1. Overview & Objectives

PostgreSQL wire communication runs over TCP (and optionally TLS), where packets can arrive in fragments across multiple `recv` calls, or multiple protocol messages can arrive in a single `recv` chunk. 

`OPG-201` implements the stream transport layer and message accumulator:
1. **Stream Transport Interface (`Stream_Transport`)**: Procedural virtual table abstracting underlying I/O (`read`, `write`, `close`), providing an immediate implementation for `core:net.TCP_Socket` and enabling zero-churn dynamic TLS wrapping in `OPG-205`.
2. **Dynamic Stream Buffer (`Stream_Buffer`)**: Accumulates bytes until complete PostgreSQL 3.0 backend messages (`1 byte type + 4 byte Big-Endian length`) are available in memory.
3. **Zero-Copy Parser Bridge**: Bridges directly to `pgproto.parse_message` using `temp_allocator`.
4. **Buffer Compaction**: Manages read/write offsets efficiently and compacts buffer when consumed data reaches a configurable threshold.
5. **Error & Timeout Mapping**: Maps `core:net.Network_Error` and disconnection states into `pgerr.Net_Error` (`.Socket_Closed`, `.Timeout`, `.Recv_Failed`, etc.).

---

## 2. Architecture & Data Structures

```odin
package pgconn

import "core:mem"
import "core:net"
import "core:time"
import "../pgerr"
import "../pgproto"

// Stream_Transport provides polymorphic I/O over TCP sockets or future TLS streams.
Stream_Transport :: struct {
	data:     rawptr,
	read:     proc(transport: rawptr, buf: []byte) -> (bytes_read: int, err: pgerr.Error),
	write:    proc(transport: rawptr, data: []byte) -> (bytes_written: int, err: pgerr.Error),
	close:    proc(transport: rawptr),
	set_deadlines: proc(transport: rawptr, read_timeout, write_timeout: time.Duration) -> pgerr.Error,
}

// TCP_Transport_Data is the concrete transport state for plain TCP sockets.
TCP_Transport_Data :: struct {
	socket:        net.TCP_Socket,
	read_timeout:  time.Duration,
	write_timeout: time.Duration,
}

// Stream_Buffer accumulates incoming bytes and manages outbound writes.
Stream_Buffer :: struct {
	transport:          Stream_Transport,
	buf:                [dynamic]byte,
	read_offset:        int,
	write_offset:       int,
	allocator:          mem.Allocator,
	compact_threshold:  int, // Bytes consumed before shifting remaining bytes (default 4096)
}
```

---

## 3. Procedural API Specification

### 3.1 Transport Constructors

```odin
// Creates a Stream_Transport wrapping a native core:net.TCP_Socket
make_tcp_transport(data: ^TCP_Transport_Data, socket: net.TCP_Socket) -> Stream_Transport
```

### 3.2 Stream Management

```odin
// Initializes a stream buffer with the given transport and initial capacity
stream_init(
	s: ^Stream_Buffer,
	transport: Stream_Transport,
	initial_capacity := 8192,
	compact_threshold := 4096,
	allocator := context.allocator,
)

// Destroys the stream buffer and frees its internal memory
stream_destroy(s: ^Stream_Buffer)

// Closes the underlying transport
stream_close(s: ^Stream_Buffer)
```

### 3.3 Message Reading & Accumulation

```odin
// Reads from the transport until at least one complete PostgreSQL backend message is available,
// then parses and returns it. Uses temp_allocator for transient parsing allocations.
stream_read_message(
	s: ^Stream_Buffer,
	temp_allocator := context.temp_allocator,
) -> (
	msg: pgproto.Backend_Message,
	err: pgerr.Error,
)
```

#### Detailed Accumulator Semantics:
1. **Framing Check**:
   - Available unparsed bytes = `s.write_offset - s.read_offset`.
   - If available < 5 bytes: call `s.transport.read` to fill more bytes.
   - Read 1-byte message type and 4-byte big-endian length `msg_len` from `s.buf[s.read_offset : s.read_offset + 5]`.
   - Total packet size = `1 + int(msg_len)`.
   - If `msg_len < 4`: return `pgerr.Protocol_Error{type = .Invalid_Length}`.
2. **Buffer Expansion & Reading**:
   - While available unparsed bytes < total packet size:
     - If buffer capacity is insufficient, expand dynamic buffer.
     - Call `s.transport.read` to read next chunk into `s.buf[s.write_offset:]`.
     - On read error or EOF (0 bytes read), map and return `pgerr.Net_Error`.
3. **Parse & Advance**:
   - Slice packet: `packet_bytes := s.buf[s.read_offset : s.read_offset + total_packet_size]`.
   - Parse: `msg = pgproto.parse_message(packet_bytes, allocator = temp_allocator) or_return`.
   - Advance: `s.read_offset += total_packet_size`.
4. **Compaction**:
   - If `s.read_offset >= s.compact_threshold`:
     - If `s.read_offset == s.write_offset`: reset both offsets to 0.
     - Otherwise: move remaining unparsed bytes `s.buf[s.read_offset : s.write_offset]` to `s.buf[0:]`, and adjust offsets.

### 3.4 Outbound Message Writing & Flushing

```odin
// Writes one or more message byte slices directly through the transport.
stream_write_messages(
	s: ^Stream_Buffer,
	msgs: ..[]byte,
) -> (
	err: pgerr.Error,
)
```

---

## 4. Error Mapping Matrix

| `core:net` Condition / Return | `pgerr.Net_Error` Type |
|---|---|
| `bytes_read == 0` (clean peer disconnect / EOF) | `.Socket_Closed` |
| `net.TCP_Recv_Error.Timeout` | `.Timeout` |
| `net.TCP_Recv_Error.Connection_Closed` / `.Connection_Reset` | `.Socket_Closed` |
| `net.TCP_Recv_Error.Host_Unreachable` | `.Host_Unreachable` |
| `net.TCP_Send_Error.Timeout` | `.Timeout` |
| `net.TCP_Send_Error.Connection_Closed` / `.Connection_Reset` | `.Socket_Closed` |
| Other network errors | `.Recv_Failed` / `.Send_Failed` |

---

## 5. Verification & Test Plan (`pgconn/stream_test.odin`)

To ensure unit tests run with **zero network dependencies** while maintaining $\ge 95\%$ coverage:

1. **Mock Transport**:
   - Implement `Mock_Transport` that serves predefined byte chunks (single bytes, split packets, multi-message batches, simulated timeouts, simulated EOF).
2. **Test Cases**:
   - **Full Single Packet**: Stream parses `ReadyForQuery`, `RowDescription`, `DataRow`.
   - **Fragmented Header**: Read arrives 2 bytes, then 3 bytes, then payload.
   - **Fragmented Payload**: 1000-byte message arrives in 50-byte TCP chunks.
   - **Multiple Packets in Single Read**: Single 128-byte read contains 3 distinct protocol messages; verify sequential `stream_read_message` calls drain them without loss.
   - **Buffer Compaction**: Verify buffer compaction occurs and retains partial unread bytes correctly.
   - **Invalid Length Handling**: Negative length or length $< 4$ returns `.Invalid_Length`.
   - **EOF & Disconnection Handling**: Simulating EOF returns `Net_Error{type = .Socket_Closed}`.
   - **Timeout Handling**: Simulating timeout returns `Net_Error{type = .Timeout}`.
   - **Outbound Multi-Write**: Verify `stream_write_messages` sends contiguous packets correctly.
3. **Leak-Free Tracking**:
   - All tests run with `core:mem.Tracking_Allocator` verifying 0 byte leaks.
4. **Style & Linters**:
   - `odin test pgconn -vet -strict-style`
   - `odin test pgconn -sanitize:address`

# Go Refactoring Plan (Performance Optimized)

I will refactor the Node.js project into a high-performance, single-binary Go application, removing the Nezha monitoring components.

## 1. Project Initialization
- Initialize Go module `super-tunnel`.
- Dependencies: 
    - `github.com/gorilla/websocket`: For standard-compliant, high-performance WS handling.
    - `github.com/google/uuid`: For robust UUID parsing.

## 2. Core Infrastructure (Main Loop)
- **Config**: Load `UUID`, `PORT`, `WSPATH` from env.
- **Router**: Use `net/http` for path routing (`/`, `/${SUB_PATH}`, `/${WSPATH}`).
- **Memory Optimization**: Use `sync.Pool` for buffer reuse during I/O copying to minimize GC pressure (Critical for Go network performance).

## 3. Protocol Parsers (Zero-Copy approach where possible)
- **VLESS**: 
    - Parse protocol headers directly from the WebSocket stream.
    - Validate UUID.
    - Extract Target Address (IP/Domain + Port).
- **Trojan**:
    - Calculate SHA224 of the local UUID once at startup.
    - Validate incoming connection hash.
    - Extract Target Address.

## 4. High-Performance Forwarding
- Implement a `wsConnAdapter` to wrap `*websocket.Conn` as `io.ReadWriteCloser`.
- **Data Pump**: Use `io.CopyBuffer` with recycled buffers (from `sync.Pool`) to forward data between the WebSocket and the target TCP connection.
- **Concurrency**: Each connection runs in its own lightweight Goroutine.

## 5. Auxiliary Features
- **Subscription**: Re-implement `/sub` to generate the Base64 VLESS/Trojan links.
- **ISP Check**: Simple HTTP client to fetch metadata from Cloudflare (with timeout).
- **Fake Site**: Serve a simple static response or file for root path.

## 6. Build & Delivery
- Create a `Makefile` for easy compilation (supporting Linux/Windows/macOS builds).
- Verify the binary size and basic functionality.

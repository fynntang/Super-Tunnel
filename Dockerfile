# Build Stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git for fetching dependencies
RUN apk add --no-cache git

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go ./

# Build the binary
# CGO_ENABLED=0 creates a statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -o super-tunnel main.go

# Final Stage
FROM alpine:latest

WORKDIR /app

# Install ca-certificates for HTTPS requests (Cloudflare ISP check)
RUN apk --no-cache add ca-certificates tzdata

# Copy binary from builder
COPY --from=builder /app/super-tunnel .
COPY --from=builder /app/index.html ./index.html 2>/dev/null || true

# Expose port
EXPOSE 3000

# Run
CMD ["./super-tunnel"]

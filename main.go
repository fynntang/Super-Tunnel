package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Configuration
var (
	UUID     string
	PORT     string
	WSPATH   string
	SUB_PATH string
	DOMAIN   string
	NAME     string
	PROXY_IP string

	// Computed
	uuidBytes  []byte
	trojanHash string
)

// Global State
var (
	ISP string = "Unknown"
)

// WebSocket Upgrader
var upgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Buffer Pool for zero-copy forwarding
var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

func init() {
	UUID = getEnv("UUID", "5efabea4-f6d4-91fd-b8f0-17e004c89c60")
	PORT = getEnv("PORT", "3000")
	WSPATH = getEnv("WSPATH", "")
	if WSPATH == "" {
		WSPATH = strings.ReplaceAll(UUID, "-", "")[:8]
	}
	SUB_PATH = getEnv("SUB_PATH", "sub")
	DOMAIN = getEnv("DOMAIN", "localhost")
	NAME = getEnv("NAME", "")
	PROXY_IP = getEnv("PROXY_IP", "cdns.doon.eu.org")

	parsedUUID, err := uuid.Parse(UUID)
	if err != nil {
		log.Fatalf("Invalid UUID: %v", err)
	}
	uuidBytes = parsedUUID[:]

	hash := sha256.Sum224([]byte(UUID))
	trojanHash = hex.EncodeToString(hash[:])
}

func main() {
	go getISP()

	http.HandleFunc("/", rootHandler)
	http.HandleFunc(fmt.Sprintf("/%s", SUB_PATH), subHandler)
	http.HandleFunc(fmt.Sprintf("/%s/yaml", SUB_PATH), clashHandler)
	http.HandleFunc(fmt.Sprintf("/%s", WSPATH), wsHandler)

	log.Printf("Server starting on port %s", PORT)
	log.Printf("VLESS/Trojan Path: /%s", WSPATH)
	log.Printf("Subscription Path: /%s", SUB_PATH)
	log.Printf("Subscription Path: /%s/yaml", SUB_PATH)

	err := http.ListenAndServe(":"+PORT, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// --- Handlers ---

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat("index.html"); err == nil {
		http.ServeFile(w, r, "index.html")
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello world!"))
}

func subHandler(w http.ResponseWriter, r *http.Request) {
	namePart := ISP
	if NAME != "" {
		namePart = fmt.Sprintf("%s-%s", NAME, ISP)
	}

	vlessLink := fmt.Sprintf("vless://%s@cdns.doon.eu.org:443?encryption=none&security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%%2F%s#%s",
		UUID, DOMAIN, DOMAIN, WSPATH, namePart)
	trojanLink := fmt.Sprintf("trojan://%s@cdns.doon.eu.org:443?security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%%2F%s#%s",
		UUID, DOMAIN, DOMAIN, WSPATH, namePart)

	subscription := vlessLink + "\n" + trojanLink
	base64Content := base64.StdEncoding.EncodeToString([]byte(subscription))

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(base64Content + "\n"))
}

func clashHandler(w http.ResponseWriter, r *http.Request) {
	namePart := ISP
	if NAME != "" {
		namePart = fmt.Sprintf("%s-%s", NAME, ISP)
	}

	clashConfig := fmt.Sprintf(`port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: :9090
proxies:
  - name: %s-VLESS
    type: vless
    server: %s
    port: 443
    uuid: %s
    udp: true
    tls: true
    skip-cert-verify: true
    servername: %s
    network: ws
    ws-opts:
      path: /%s
      headers:
        Host: %s
  - name: %s-Trojan
    type: trojan
    server: %s
    port: 443
    password: %s
    udp: true
    sni: %s
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /%s
      headers:
        Host: %s

proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
      - %s-VLESS
      - %s-Trojan
  - name: ♻️ 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
      - %s-VLESS
      - %s-Trojan

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
`,
		namePart, PROXY_IP, UUID, DOMAIN, WSPATH, DOMAIN,
		namePart, PROXY_IP, UUID, DOMAIN, WSPATH, DOMAIN,
		namePart, namePart,
		namePart, namePart)

	w.Header().Set("Content-Type", "text/yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.yaml\"", namePart))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(clashConfig))
}

func getISP() {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://speed.cloudflare.com/meta")
	if err != nil {
		log.Printf("Failed to get ISP: %v", err)
		return
	}
	defer resp.Body.Close()

	var data struct {
		Country        string `json:"country"`
		AsOrganization string `json:"asOrganization"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return
	}
	ISP = fmt.Sprintf("%s-%s", data.Country, data.AsOrganization)
	ISP = strings.ReplaceAll(ISP, " ", "_")
	log.Printf("ISP Identified: %s", ISP)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket Upgrade failed: %v", err)
		return
	}
	go handleConnection(wsConn)
}

// --- Connection Logic ---

func handleConnection(wsConn *websocket.Conn) {
	defer wsConn.Close()

	// Read first message to detect protocol
	msgType, firstMsg, err := wsConn.ReadMessage()
	if err != nil {
		return
	}
	if msgType != websocket.BinaryMessage {
		return
	}

	// Detect VLESS
	isVless := false
	if len(firstMsg) > 17 && firstMsg[0] == 0 {
		uuidMatch := true
		for i := 0; i < 16; i++ {
			if firstMsg[1+i] != uuidBytes[i] {
				uuidMatch = false
				break
			}
		}
		if uuidMatch {
			isVless = true
		}
	}

	if isVless {
		handleVless(wsConn, firstMsg)
	} else {
		handleTrojan(wsConn, firstMsg)
	}
}

func handleVless(wsConn *websocket.Conn, msg []byte) {
	// Parse VLESS
	// [Version(1)][UUID(16)][AddonsLen(1)][Addons(N)][Command(1)][Port(2)][AddrType(1)][Addr...]

	if len(msg) < 19 {
		return
	}

	addonsLen := int(msg[17])
	parseIndex := 17 + 1 + addonsLen

	if len(msg) < parseIndex+1 {
		return
	}

	// Command byte is at parseIndex.
	// Node code: let i = msg.slice(17, 18).readUInt8() + 19;
	// 17(len byte) + 1(len val) + 1(cmd byte) = 19?
	// If len=0. parseIndex=18.
	// Node: i = 0 + 19 = 19.
	// So command is skipped. parseIndex points to Port?
	// Let's verify Node code:
	// let i = msg.slice(17, 18).readUInt8() + 19;
	// const port = msg.slice(i, i += 2).readUInt16BE(0);
	// Yes, 'i' starts at Port.
	// So we need to skip Command byte (1 byte).

	parseIndex += 1 // Skip Command

	if len(msg) < parseIndex+2 {
		return
	}

	port := binary.BigEndian.Uint16(msg[parseIndex : parseIndex+2])
	parseIndex += 2

	if len(msg) < parseIndex+1 {
		return
	}

	atyp := msg[parseIndex]
	parseIndex++

	var host string
	switch atyp {
	case 1: // IPv4
		if len(msg) < parseIndex+4 {
			return
		}
		host = net.IP(msg[parseIndex : parseIndex+4]).String()
		parseIndex += 4
	case 2: // Domain
		if len(msg) < parseIndex+1 {
			return
		}
		domainLen := int(msg[parseIndex])
		parseIndex++
		if len(msg) < parseIndex+domainLen {
			return
		}
		host = string(msg[parseIndex : parseIndex+domainLen])
		parseIndex += domainLen
	case 3: // IPv6
		if len(msg) < parseIndex+16 {
			return
		}
		host = net.IP(msg[parseIndex : parseIndex+16]).String()
		parseIndex += 16
	default:
		return
	}

	// Send VLESS Response Header: [Version][AddonsLen]
	// Node: ws.send(new Uint8Array([VERSION, 0]));
	if err := wsConn.WriteMessage(websocket.BinaryMessage, []byte{msg[0], 0}); err != nil {
		return
	}

	// Connect to Target
	targetAddr := fmt.Sprintf("%s:%d", host, port)
	dialAndForward(wsConn, targetAddr, msg[parseIndex:])
}

func handleTrojan(wsConn *websocket.Conn, msg []byte) {
	// [Hash(56)][CRLF(2)][Cmd(1)][Atyp(1)][Addr...][Port(2)][CRLF(2)]
	// Node code supports optional CRLF after hash.

	if len(msg) < 56 {
		return
	}

	receivedHash := string(msg[:56])
	if receivedHash != trojanHash {
		return
	}

	parseIndex := 56
	if len(msg) >= parseIndex+2 && msg[parseIndex] == 0x0d && msg[parseIndex+1] == 0x0a {
		parseIndex += 2
	}

	if len(msg) < parseIndex+1 {
		return
	}
	cmd := msg[parseIndex]
	if cmd != 1 { // CONNECT
		return
	}
	parseIndex++

	if len(msg) < parseIndex+1 {
		return
	}
	atyp := msg[parseIndex]
	parseIndex++

	var host string
	switch atyp {
	case 1: // IPv4
		if len(msg) < parseIndex+4 {
			return
		}
		host = net.IP(msg[parseIndex : parseIndex+4]).String()
		parseIndex += 4
	case 3: // Domain
		if len(msg) < parseIndex+1 {
			return
		}
		domainLen := int(msg[parseIndex])
		parseIndex++
		if len(msg) < parseIndex+domainLen {
			return
		}
		host = string(msg[parseIndex : parseIndex+domainLen])
		parseIndex += domainLen
	case 4: // IPv6
		if len(msg) < parseIndex+16 {
			return
		}
		host = net.IP(msg[parseIndex : parseIndex+16]).String()
		parseIndex += 16
	default:
		return
	}

	if len(msg) < parseIndex+2 {
		return
	}
	port := binary.BigEndian.Uint16(msg[parseIndex : parseIndex+2])
	parseIndex += 2

	// Node: Skip optional CRLF after port
	if len(msg) >= parseIndex+2 && msg[parseIndex] == 0x0d && msg[parseIndex+1] == 0x0a {
		parseIndex += 2
	}

	targetAddr := fmt.Sprintf("%s:%d", host, port)
	dialAndForward(wsConn, targetAddr, msg[parseIndex:])
}

func dialAndForward(wsConn *websocket.Conn, targetAddr string, payload []byte) {
	// Dial Target
	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		// Try resolving manually if simple Dial fails (optional, standard Dial usually works)
		// Node code had custom resolveHost. Go's net.Dial is usually enough.
		return
	}
	defer conn.Close()

	// Write payload (remaining bytes from first message)
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return
		}
	}

	// Wrap WebSocket
	wsStream := &wsConnAdapter{conn: wsConn}

	// Bidirectional Copy
	// Use ErrGroup or simple goroutine
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		io.CopyBuffer(conn, wsStream, buf)
		conn.(*net.TCPConn).CloseWrite() // Close write side of TCP
	}()

	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		io.CopyBuffer(wsStream, conn, buf)
		// When TCP closes read, we close WS
		wsConn.Close()
	}()

	wg.Wait()
}

// --- WS Adapter ---

type wsConnAdapter struct {
	conn   *websocket.Conn
	reader io.Reader
}

func (a *wsConnAdapter) Read(p []byte) (int, error) {
	for {
		if a.reader == nil {
			_, reader, err := a.conn.NextReader()
			if err != nil {
				return 0, err
			}
			a.reader = reader
		}
		n, err := a.reader.Read(p)
		if err == io.EOF {
			a.reader = nil
			continue
		}
		return n, err
	}
}

func (a *wsConnAdapter) Write(p []byte) (int, error) {
	err := a.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

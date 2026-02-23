package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mdp/qrterminal/v3"
)

var verboseRelayLogs = os.Getenv("SP_VERBOSE_LOG") == "1"

func debugf(format string, v ...any) {
	if verboseRelayLogs {
		log.Printf(format, v...)
	}
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) — avoids golang.org/x/crypto dependency
// ---------------------------------------------------------------------------

func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	var out, prev []byte
	for i := byte(1); len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{i})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

// ---------------------------------------------------------------------------
// AES-256-GCM framed read / write
// Frame = [enc_length (2+16 bytes)] [enc_payload (N+16 bytes)]
// Nonce = 4-byte prefix || 8-byte counter (big-endian)
// Length uses counter*2, payload uses counter*2+1
// ---------------------------------------------------------------------------

func makeNonce(counter uint64, prefix []byte) []byte {
	n := make([]byte, 12)
	copy(n[:4], prefix)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func readFrame(r io.Reader, aead cipher.AEAD, counter uint64, prefix []byte) ([]byte, error) {
	encLen := make([]byte, 2+aead.Overhead())
	if _, err := io.ReadFull(r, encLen); err != nil {
		return nil, err
	}
	lenBuf, err := aead.Open(nil, makeNonce(counter*2, prefix), encLen, nil)
	if err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(lenBuf))
	if size == 0 {
		return nil, fmt.Errorf("zero-length frame")
	}
	encData := make([]byte, size+aead.Overhead())
	if _, err := io.ReadFull(r, encData); err != nil {
		return nil, err
	}
	return aead.Open(nil, makeNonce(counter*2+1, prefix), encData, nil)
}

func writeFrame(w io.Writer, aead cipher.AEAD, counter uint64, prefix []byte, data []byte) error {
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))
	encLen := aead.Seal(nil, makeNonce(counter*2, prefix), lenBuf, nil)
	encData := aead.Seal(nil, makeNonce(counter*2+1, prefix), data, nil)
	buf := make([]byte, 0, len(encLen)+len(encData))
	buf = append(buf, encLen...)
	buf = append(buf, encData...)
	_, err := w.Write(buf)
	return err
}

// ---------------------------------------------------------------------------
// SOCKS5-style target address parser
// ---------------------------------------------------------------------------

func parseTarget(data []byte) (string, error) {
	if len(data) < 4 {
		return "", fmt.Errorf("address too short")
	}
	switch data[0] {
	case 1: // IPv4
		if len(data) < 7 {
			return "", fmt.Errorf("short ipv4")
		}
		return fmt.Sprintf("%s:%d", net.IP(data[1:5]), binary.BigEndian.Uint16(data[5:7])), nil
	case 3: // Domain
		dlen := int(data[1])
		if len(data) < 2+dlen+2 {
			return "", fmt.Errorf("short domain")
		}
		return fmt.Sprintf("%s:%d", data[2:2+dlen], binary.BigEndian.Uint16(data[2+dlen:4+dlen])), nil
	case 4: // IPv6
		if len(data) < 19 {
			return "", fmt.Errorf("short ipv6")
		}
		return fmt.Sprintf("[%s]:%d", net.IP(data[1:17]), binary.BigEndian.Uint16(data[17:19])), nil
	}
	return "", fmt.Errorf("unknown address type %d", data[0])
}

// ---------------------------------------------------------------------------
// Nonce replay cache
// ---------------------------------------------------------------------------

type NonceCache struct {
	mu sync.Mutex
	m  map[[32]byte]int64
}

func newNonceCache() *NonceCache {
	nc := &NonceCache{m: make(map[[32]byte]int64)}
	go func() {
		for range time.Tick(60 * time.Second) {
			nc.mu.Lock()
			cutoff := time.Now().Unix() - 120
			for k, v := range nc.m {
				if v < cutoff {
					delete(nc.m, k)
				}
			}
			nc.mu.Unlock()
		}
	}()
	return nc
}

func (nc *NonceCache) check(nonce []byte) bool {
	var key [32]byte
	copy(key[:], nonce)
	nc.mu.Lock()
	defer nc.mu.Unlock()
	if _, ok := nc.m[key]; ok {
		return false
	}
	nc.m[key] = time.Now().Unix()
	return true
}

// ---------------------------------------------------------------------------
// Anti-probe: on auth failure, behave like a random service
// ---------------------------------------------------------------------------

func drainAndClose(conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	junk := make([]byte, 256)
	io.ReadAtLeast(conn, junk, 1)
	reply := make([]byte, 64)
	rand.Read(reply)
	conn.Write(reply)
	conn.Close()
}

// ---------------------------------------------------------------------------
// Connection handler
//
// Handshake (client → server):
//   [nonce 32B] [timestamp 8B BE] [HMAC-SHA256 32B] [pad_len 2B BE] [padding 32-256B]
//
// After auth, derive directional keys via HKDF:
//   c2s_key = HKDF(psk, nonce, "simple-c2s", 32)
//   s2c_key = HKDF(psk, nonce, "simple-s2c", 32)
//
// First encrypted frame from client = SOCKS5-style target address.
// Then bidirectional relay with AES-256-GCM framed encryption.
// ---------------------------------------------------------------------------

func handle(conn net.Conn, psk []byte, nc *NonceCache) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	debugf("[%s] new connection", remoteAddr)
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	hdr := make([]byte, 74) // 32 nonce + 8 ts + 32 hmac + 2 padlen
	if _, err := io.ReadFull(conn, hdr); err != nil {
		log.Printf("[%s] failed to read header: %v", remoteAddr, err)
		drainAndClose(conn)
		return
	}

	nonce := hdr[:32]
	tsBytes := hdr[32:40]
	tag := hdr[40:72]
	padLen := binary.BigEndian.Uint16(hdr[72:74])

	debugf("[%s] handshake: padLen=%d noncePrefix=%x", remoteAddr, padLen, nonce[:4])

	if padLen < 32 || padLen > 256 {
		log.Printf("[%s] bad padLen %d (not in 32..256)", remoteAddr, padLen)
		drainAndClose(conn)
		return
	}
	pad := make([]byte, padLen)
	if _, err := io.ReadFull(conn, pad); err != nil {
		log.Printf("[%s] failed to read padding: %v", remoteAddr, err)
		drainAndClose(conn)
		return
	}

	// Verify timestamp (±30 s window)
	ts := int64(binary.BigEndian.Uint64(tsBytes))
	now := time.Now().Unix()
	diff := now - ts
	debugf("[%s] timestamp: client=%d server=%d diff=%d", remoteAddr, ts, now, diff)
	if diff < -30 || diff > 30 {
		log.Printf("[%s] REJECTED: timestamp out of range (diff=%d)", remoteAddr, diff)
		drainAndClose(conn)
		return
	}

	// Verify HMAC-SHA256(psk, nonce || timestamp)
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	mac.Write(tsBytes)
	expected := mac.Sum(nil)
	if !hmac.Equal(tag, expected) {
		log.Printf("[%s] REJECTED: HMAC mismatch", remoteAddr)
		log.Printf("[%s]   got:      %x", remoteAddr, tag)
		log.Printf("[%s]   expected: %x", remoteAddr, expected)
		drainAndClose(conn)
		return
	}

	// Anti-replay
	if !nc.check(nonce) {
		log.Printf("[%s] REJECTED: nonce replay", remoteAddr)
		drainAndClose(conn)
		return
	}

	debugf("[%s] auth OK, deriving keys", remoteAddr)

	// Derive directional session keys
	prefix := nonce[:4]
	c2sKey := hkdfSHA256(psk, nonce, []byte("simple-c2s"), 32)
	s2cKey := hkdfSHA256(psk, nonce, []byte("simple-s2c"), 32)

	c2sBlock, _ := aes.NewCipher(c2sKey)
	c2sAEAD, _ := cipher.NewGCM(c2sBlock)
	s2cBlock, _ := aes.NewCipher(s2cKey)
	s2cAEAD, _ := cipher.NewGCM(s2cBlock)

	// First frame — detect mux vs legacy single-stream mode
	firstFrame, err := readFrame(conn, c2sAEAD, 0, prefix)
	if err != nil {
		log.Printf("[%s] failed to read first frame: %v", remoteAddr, err)
		return
	}

	// Mux init: first byte 0x00
	if len(firstFrame) >= 4 && firstFrame[0] == 0x00 {
		debugf("[%s] entering mux mode (version=%d)", remoteAddr, firstFrame[1])
		conn.SetDeadline(time.Time{})
		handleMux(conn, c2sAEAD, s2cAEAD, prefix, remoteAddr)
		return
	}

	// Legacy single-stream mode
	debugf("[%s] legacy mode — target bytes: %x (len=%d)", remoteAddr, firstFrame, len(firstFrame))
	target, err := parseTarget(firstFrame)
	if err != nil {
		log.Printf("[%s] failed to parse target: %v", remoteAddr, err)
		return
	}

	debugf("[%s] connecting to target: %s", remoteAddr, target)
	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[%s] failed to connect to target %s: %v", remoteAddr, target, err)
		return
	}
	defer remote.Close()
	log.Printf("[%s] session established target=%s", remoteAddr, target)

	conn.SetDeadline(time.Time{}) // clear deadline for relay

	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Remote (decrypt, then forward plaintext)
	go func() {
		defer wg.Done()
		counter := uint64(1) // 0 was consumed by the target-address frame
		var totalBytes int64
		for {
			data, err := readFrame(conn, c2sAEAD, counter, prefix)
			if err != nil {
				debugf("[%s] c2r read done (counter=%d, totalBytes=%d): %v", remoteAddr, counter, totalBytes, err)
				if tcpRemote, ok := remote.(*net.TCPConn); ok {
					_ = tcpRemote.CloseWrite()
				}
				return
			}
			if _, err := remote.Write(data); err != nil {
				log.Printf("[%s] c2r write error (counter=%d): %v", remoteAddr, counter, err)
				if tcpRemote, ok := remote.(*net.TCPConn); ok {
					_ = tcpRemote.CloseWrite()
				}
				return
			}
			totalBytes += int64(len(data))
			counter++
		}
	}()

	// Remote → Client (read plaintext, encrypt, send)
	go func() {
		defer wg.Done()
		counter := uint64(0)
		var totalBytes int64
		buf := make([]byte, 16384)
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				if werr := writeFrame(conn, s2cAEAD, counter, prefix, buf[:n]); werr != nil {
					log.Printf("[%s] r2c write error (counter=%d): %v", remoteAddr, counter, werr)
					return
				}
				totalBytes += int64(n)
				counter++
			}
			if err != nil {
				debugf("[%s] r2c read done (counter=%d, totalBytes=%d): %v", remoteAddr, counter, totalBytes, err)
				if tcpClient, ok := conn.(*net.TCPConn); ok {
					_ = tcpClient.CloseWrite()
				}
				return
			}
		}
	}()

	wg.Wait()
	_ = remote.Close()
	_ = conn.Close()
}

// ---------------------------------------------------------------------------
// Mux protocol constants
// ---------------------------------------------------------------------------

const (
	muxCmdConnect     = 0x01
	muxCmdConnectOK   = 0x02
	muxCmdConnectFail = 0x03
	muxCmdData        = 0x04
	muxCmdFIN         = 0x05
)

type muxStream struct {
	id     uint32
	remote net.Conn
}

// ---------------------------------------------------------------------------
// Multiplexed connection handler
//
// After handshake + mux init frame, all frames use:
//   [cmd 1B] [streamID 4B BE] [payload...]
//
// Commands:
//   0x01 CONNECT      C→S  payload = SOCKS5-style target address
//   0x02 CONNECT_OK   S→C  payload = empty
//   0x03 CONNECT_FAIL S→C  payload = UTF-8 error string
//   0x04 DATA         both payload = raw data
//   0x05 FIN          both payload = empty (half-close)
// ---------------------------------------------------------------------------

func handleMux(conn net.Conn, c2sAEAD, s2cAEAD cipher.AEAD, prefix []byte, remoteAddr string) {
	var writeMu sync.Mutex
	var writeCounter uint64

	streams := make(map[uint32]*muxStream)
	var streamsMu sync.Mutex
	var wg sync.WaitGroup

	safeWriteFrame := func(data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		err := writeFrame(conn, s2cAEAD, writeCounter, prefix, data)
		if err == nil {
			writeCounter++
		}
		return err
	}

	sendMux := func(cmd byte, streamID uint32, payload []byte) error {
		frame := make([]byte, 5+len(payload))
		frame[0] = cmd
		binary.BigEndian.PutUint32(frame[1:5], streamID)
		if len(payload) > 0 {
			copy(frame[5:], payload)
		}
		return safeWriteFrame(frame)
	}

	// Relay: remote target → encrypted client
	startRemoteReader := func(s *muxStream) {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := s.remote.Read(buf)
			if n > 0 {
				if werr := sendMux(muxCmdData, s.id, buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				debugf("[%s] mux stream %d remote read done: %v", remoteAddr, s.id, err)
				break
			}
		}
		_ = sendMux(muxCmdFIN, s.id, nil)
	}

	log.Printf("[%s] mux session started", remoteAddr)

	// Read mux frames from client
	readCounter := uint64(1) // 0 was consumed by the mux-init frame
	for {
		data, err := readFrame(conn, c2sAEAD, readCounter, prefix)
		if err != nil {
			debugf("[%s] mux read ended: %v", remoteAddr, err)
			break
		}
		readCounter++

		if len(data) < 5 {
			continue
		}

		cmd := data[0]
		streamID := binary.BigEndian.Uint32(data[1:5])
		payload := data[5:]

		switch cmd {
		case muxCmdConnect:
			target, terr := parseTarget(payload)
			if terr != nil {
				_ = sendMux(muxCmdConnectFail, streamID, []byte(terr.Error()))
				continue
			}
			// Dial asynchronously to prevent head-of-line blocking.
			// A slow dial (e.g. unreachable host) must not block the
			// read loop, otherwise ALL mux streams stall.
			wg.Add(1)
			go func(sid uint32, addr string) {
				defer wg.Done()
				remote, derr := net.DialTimeout("tcp", addr, 10*time.Second)
				if derr != nil {
					_ = sendMux(muxCmdConnectFail, sid, []byte(derr.Error()))
					return
				}
				s := &muxStream{id: sid, remote: remote}
				streamsMu.Lock()
				streams[sid] = s
				streamsMu.Unlock()
				if err := sendMux(muxCmdConnectOK, sid, nil); err != nil {
					remote.Close()
					streamsMu.Lock()
					delete(streams, sid)
					streamsMu.Unlock()
					return
				}
				debugf("[%s] mux stream %d → %s", remoteAddr, sid, addr)
				wg.Add(1)
				go startRemoteReader(s)
			}(streamID, target)

		case muxCmdData:
			streamsMu.Lock()
			s := streams[streamID]
			streamsMu.Unlock()
			if s != nil {
				if _, werr := s.remote.Write(payload); werr != nil {
					debugf("[%s] mux stream %d write error: %v", remoteAddr, streamID, werr)
					streamsMu.Lock()
					delete(streams, streamID)
					streamsMu.Unlock()
					s.remote.Close()
				}
			}

		case muxCmdFIN:
			streamsMu.Lock()
			s := streams[streamID]
			streamsMu.Unlock()
			if s != nil {
				if tcp, ok := s.remote.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
			}
		}
	}

	// Cleanup: close all streams
	streamsMu.Lock()
	for _, s := range streams {
		s.remote.Close()
	}
	streamsMu.Unlock()

	wg.Wait()
	log.Printf("[%s] mux session ended", remoteAddr)
}

// ---------------------------------------------------------------------------
// TCP server
// ---------------------------------------------------------------------------

func serve(port int, psk []byte) {
	nc := newNonceCache()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	log.Printf("listening on %s (dual-stack, PSK prefix: %x...)", ln.Addr(), psk[:4])
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handle(conn, psk, nc)
	}
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func httpGetBody(url string, timeout time.Duration) string {
	c := &http.Client{Timeout: timeout}
	resp, err := c.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body))
}

func getPublicIPv4() string {
	// Try overseas service first, then CN-accessible fallbacks
	urls := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://myip.ipip.net/ip",
		"https://4.ipw.cn",
	}
	for _, u := range urls {
		if ip := httpGetBody(u, 8*time.Second); ip != "" {
			// some services return extra text; extract first valid IPv4
			if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
				return ip
			}
		}
	}
	return ""
}

func getPublicIPv6() string {
	urls := []string{
		"https://api6.ipify.org",
		"https://6.ipw.cn",
	}
	for _, u := range urls {
		if ip := httpGetBody(u, 6*time.Second); ip != "" {
			if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
				return ip
			}
		}
	}
	return ""
}

func resolvePublicIPs() (ipv4, ipv6 string) {
	// If user explicitly set SP_SERVER_IP, skip auto-detection entirely
	if env := strings.TrimSpace(os.Getenv("SP_SERVER_IP")); env != "" {
		log.Printf("Using SP_SERVER_IP=%s from environment", env)
		return env, ""
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ipv4 = getPublicIPv4() }()
	go func() { defer wg.Done(); ipv6 = getPublicIPv6() }()
	wg.Wait()
	return
}

func promptForIP() string {
	fmt.Println()
	fmt.Println("  ⚠  Could not auto-detect server IP address.")
	fmt.Print("  Please enter your server IP (or domain): ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			return ip
		}
	}
	fmt.Println("  No IP entered, using placeholder 'YOUR_SERVER_IP'.")
	return "YOUR_SERVER_IP"
}

func loadOrCreatePSK(path string) []byte {
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	if data, err := os.ReadFile(path); err == nil {
		if psk, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil && len(psk) == 32 {
			return psk
		}
	}
	psk := make([]byte, 32)
	rand.Read(psk)
	os.WriteFile(path, []byte(hex.EncodeToString(psk)+"\n"), 0600)
	return psk
}

func b64url(data []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data)
}

func defaultPSKPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ".simple-psk"
	}
	return filepath.Join(home, ".simpleproxy", "psk.hex")
}

// ---------------------------------------------------------------------------
// Main — prints connection info + QR, then daemonises the listener
// ---------------------------------------------------------------------------

func main() {
	port := flag.Int("p", 23333, "listen port")
	fg := flag.Bool("fg", false, "run in foreground (don't daemonise)")
	pskFile := flag.String("psk-file", defaultPSKPath(), "path to persistent PSK file")
	flag.Parse()

	// Child daemon process — just serve (with logging to file)
	if os.Getenv("_SP_DAEMON") == "1" {
		// Set up file logging for daemon
		logFile, err := os.OpenFile("/tmp/simpleserver.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			log.SetOutput(logFile)
		}
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)

		pskHex := os.Getenv("_SP_PSK")
		psk, err := hex.DecodeString(pskHex)
		if err != nil || len(psk) != 32 {
			log.Fatal("invalid PSK in daemon env")
		}
		serve(*port, psk)
		return
	}

	// Foreground mode — serve directly with console logging
	if *fg {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
		psk := loadOrCreatePSK(*pskFile)
		ipv4, ipv6 := resolvePublicIPs()
		ip := ipv4
		if ip == "" {
			ip = ipv6
		}
		if ip == "" {
			ip = promptForIP()
		}
		payload := fmt.Sprintf("%d:%s:%s", *port, hex.EncodeToString(psk), ip)
		uri := "simple://" + b64url([]byte(payload)) + "#SimpleServer"
		fmt.Printf("\n  Foreground mode\n")
		if ipv4 != "" {
			fmt.Printf("  IPv4 : %s\n", ipv4)
		}
		if ipv6 != "" {
			fmt.Printf("  IPv6 : %s\n", ipv6)
		}
		fmt.Printf("  URI  : %s\n", uri)
		fmt.Printf("  PSK file: %s\n\n", *pskFile)
		serve(*port, psk)
		return
	}

	// Parent process — setup, print info, fork daemon
	psk := loadOrCreatePSK(*pskFile)
	ipv4, ipv6 := resolvePublicIPs()
	ip := ipv4
	if ip == "" {
		ip = ipv6
	}
	if ip == "" {
		ip = promptForIP()
	}

	// Connection URI: simple://base64url(port:hexkey:host)#name
	payload := fmt.Sprintf("%d:%s:%s", *port, hex.EncodeToString(psk), ip)
	uri := "simple://" + b64url([]byte(payload)) + "#SimpleServer"

	fmt.Println()
	fmt.Println("  ╔═══════════════════════════════════════════╗")
	fmt.Println("  ║         SimpleProtocol Server             ║")
	fmt.Println("  ╚═══════════════════════════════════════════╝")
	fmt.Println()
	if ipv4 != "" {
		fmt.Printf("  IPv4     : %s\n", ipv4)
	}
	if ipv6 != "" {
		fmt.Printf("  IPv6     : %s\n", ipv6)
	}
	fmt.Printf("  Port     : %d\n", *port)
	fmt.Printf("  PSK      : %s\n", hex.EncodeToString(psk))
	fmt.Printf("  PSK file : %s\n", *pskFile)
	fmt.Println()
	fmt.Printf("  URI:\n  %s\n", uri)
	fmt.Println()

	qrterminal.Generate(uri, qrterminal.L, os.Stdout)
	fmt.Println()

	// Daemonise: re-exec self as background child with PSK in env
	cmd := exec.Command(os.Args[0], "-p", fmt.Sprintf("%d", *port))
	cmd.Env = append(os.Environ(),
		"_SP_DAEMON=1",
		"_SP_PSK="+hex.EncodeToString(psk),
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to daemonise: %v", err)
	}
	fmt.Printf("  Daemon started (PID %d)\n\n", cmd.Process.Pid)
}

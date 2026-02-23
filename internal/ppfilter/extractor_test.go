// Package ppfilter provides Proxy Protocol parsing for NetXFW.
// Package ppfilter 为 NetXFW 提供 Proxy Protocol 解析。
package ppfilter

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/utils/logger"
)

// TestNewExtractor tests the Extractor creation.
// TestNewExtractor 测试 Extractor 创建。
func TestNewExtractor(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		TrustedLBs: []string{"10.0.0.0/8"},
		CacheTTL:   5 * time.Minute,
	}

	e := NewExtractor(cfg)
	if e == nil {
		t.Fatal("Expected non-nil extractor")
	}

	if !e.enabled {
		t.Error("Expected extractor to be enabled")
	}

	if len(e.trustedLBs) != 1 {
		t.Errorf("Expected 1 trusted LB range, got %d", len(e.trustedLBs))
	}
}

// TestIsEnabled tests the IsEnabled method.
// TestIsEnabled 测试 IsEnabled 方法。
func TestIsEnabled(t *testing.T) {
	enabledCfg := &Config{Enabled: true}
	disabledCfg := &Config{Enabled: false}

	enabledExtractor := NewExtractor(enabledCfg)
	disabledExtractor := NewExtractor(disabledCfg)

	if !enabledExtractor.IsEnabled() {
		t.Error("Expected enabled extractor to return true")
	}

	if disabledExtractor.IsEnabled() {
		t.Error("Expected disabled extractor to return false")
	}
}

// TestConnectionCache tests the ConnectionCache.
// TestConnectionCache 测试 ConnectionCache。
func TestConnectionCache(t *testing.T) {
	cache := NewConnectionCache(1 * time.Minute)

	realIP, _ := netip.ParseAddr("192.168.1.100")
	lbIP, _ := netip.ParseAddr("10.0.1.100")

	connID := generateConnID(lbIP, realIP)
	info := &ConnectionInfo{
		RealIP:    realIP,
		RealPort:  12345,
		LBIP:      lbIP,
		LBPort:    80,
		Timestamp: time.Now(),
	}

	// Test Set and Get.
	// 测试 Set 和 Get。
	cache.Set(connID, info)

	retrieved := cache.Get(connID)
	if retrieved == nil {
		t.Fatal("Expected to retrieve connection info")
	}

	if retrieved.RealIP != realIP {
		t.Errorf("Expected RealIP %s, got %s", realIP, retrieved.RealIP)
	}

	// Test GetRealIP.
	// 测试 GetRealIP。
	retrievedIP, ok := cache.GetRealIP(connID)
	if !ok {
		t.Error("Expected to get real IP")
	}

	if retrievedIP != realIP {
		t.Errorf("Expected RealIP %s, got %s", realIP, retrievedIP)
	}

	// Test Delete.
	// 测试 Delete。
	cache.Delete(connID)

	_, ok = cache.GetRealIP(connID)
	if ok {
		t.Error("Expected connection info to be deleted")
	}
}

// TestBufferedConn tests the BufferedConn.
// TestBufferedConn 测试 BufferedConn。
func TestBufferedConn(t *testing.T) {
	// Create a mock connection.
	// 创建模拟连接。
	mockConn := &mockConn{}

	buf := []byte("test data")
	buffered := &BufferedConn{
		Conn: mockConn,
		buf:  buf,
	}

	// Read from buffer.
	// 从缓冲区读取。
	b := make([]byte, 100)
	n, err := buffered.Read(b)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if n != len(buf) {
		t.Errorf("Expected %d bytes, got %d", len(buf), n)
	}

	if string(b[:n]) != "test data" {
		t.Errorf("Expected 'test data', got '%s'", string(b[:n]))
	}
}

// TestProxyProtocolListener tests the ProxyProtocolListener.
// TestProxyProtocolListener 测试 ProxyProtocolListener。
func TestProxyProtocolListener(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		TrustedLBs: []string{"10.0.0.0/8"},
	}

	extractor := NewExtractor(cfg)

	// Create a mock listener.
	// 创建模拟监听器。
	mockListener := &mockListener{}

	ln := &ProxyProtocolListener{
		Listener:   mockListener,
		extractor:  extractor,
		trustedLBs: extractor.trustedLBs,
	}

	// Verify the listener was created successfully
	// 验证监听器创建成功
	if ln.Listener == nil {
		t.Fatal("Expected non-nil listener")
	}
}

// TestGenerateConnID tests the generateConnID function.
// TestGenerateConnID 测试 generateConnID 函数。
func TestGenerateConnID(t *testing.T) {
	lbIP, _ := netip.ParseAddr("10.0.1.100")
	realIP, _ := netip.ParseAddr("192.168.1.100")

	connID := generateConnID(lbIP, realIP)

	expected := "10.0.1.100:192.168.1.100"
	if connID != expected {
		t.Errorf("Expected '%s', got '%s'", expected, connID)
	}
}

// mockConn is a mock net.Conn for testing.
// mockConn 是用于测试的模拟 net.Conn。
type mockConn struct {
	net.Conn
}

func (c *mockConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (c *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (c *mockConn) Close() error {
	return nil
}

func (c *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("10.0.1.100"),
		Port: 12345,
	}
}

// mockListener is a mock net.Listener for testing.
// mockListener 是用于测试的模拟 net.Listener。
type mockListener struct {
	net.Listener
}

func (l *mockListener) Accept() (net.Conn, error) {
	return &mockConn{}, nil
}

func (l *mockListener) Close() error {
	return nil
}

func (l *mockListener) Addr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 8080,
	}
}

func init() {
	// Initialize logger for tests.
	// 为测试初始化日志器。
	logger.Init(logger.LoggingConfig{
		Enabled: false,
	})
}

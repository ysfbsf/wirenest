package serve

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Manager manages active serve configurations
type Manager struct {
	mu             sync.RWMutex
	configurations map[uint32]*ServeConfig
	netbirdIP      string // The NetBird interface IP to bind listeners to
}

// ServeConfig represents an active serve configuration
type ServeConfig struct {
	Target        string
	Port          uint32
	Protocol      string
	ListenAddress string
	Active        bool
	StartedAt     time.Time
	listener      net.Listener
	server        interface{} // *http.Server for HTTP/HTTPS, or custom TCP handler
	cancel        context.CancelFunc
}

// NewManager creates a new serve manager
func NewManager(netbirdIP string) *Manager {
	return &Manager{
		configurations: make(map[uint32]*ServeConfig),
		netbirdIP:      netbirdIP,
	}
}

// Start begins serving a local service on the NetBird network
func (m *Manager) Start(ctx context.Context, target string, port uint32, protocol string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if port is already in use
	if existingConfig, exists := m.configurations[port]; exists && existingConfig.Active {
		return fmt.Errorf("port %d is already being served", port)
	}

	// Parse and validate target URL
	targetURL, err := url.Parse(fmt.Sprintf("%s://%s", protocol, target))
	if err != nil {
		return fmt.Errorf("invalid target URL: %v", err)
	}

	// Create listen address on NetBird interface
	listenAddr := fmt.Sprintf("%s:%d", m.netbirdIP, port)

	// Create context for this serve
	serveCtx, cancel := context.WithCancel(ctx)

	config := &ServeConfig{
		Target:        target,
		Port:          port,
		Protocol:      protocol,
		ListenAddress: listenAddr,
		Active:        true,
		StartedAt:     time.Now(),
		cancel:        cancel,
	}

	var err2 error
	switch protocol {
	case "http":
		err2 = m.startHTTP(serveCtx, config, targetURL)
	case "https":
		err2 = m.startHTTPS(serveCtx, config, targetURL)
	case "tcp":
		err2 = m.startTCP(serveCtx, config, target)
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	if err2 != nil {
		cancel()
		return err2
	}

	m.configurations[port] = config
	log.Infof("Started serving %s on %s via %s", target, listenAddr, protocol)
	return nil
}

// Stop stops serving on the specified port
func (m *Manager) Stop(port uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	config, exists := m.configurations[port]
	if !exists || !config.Active {
		return fmt.Errorf("no active serve configuration on port %d", port)
	}

	return m.stopConfig(config)
}

// StopAll stops all active serves
func (m *Manager) StopAll() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	var lastErr error

	for _, config := range m.configurations {
		if config.Active {
			if err := m.stopConfig(config); err != nil {
				lastErr = err
				log.Errorf("Failed to stop serve on port %d: %v", config.Port, err)
			} else {
				count++
			}
		}
	}

	return count, lastErr
}

// GetConfigurations returns all serve configurations
func (m *Manager) GetConfigurations() []*ServeConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	configs := make([]*ServeConfig, 0, len(m.configurations))
	for _, config := range m.configurations {
		// Create a copy to avoid race conditions
		configCopy := *config
		configs = append(configs, &configCopy)
	}

	return configs
}

// stopConfig stops a specific serve configuration (must be called with mutex held)
func (m *Manager) stopConfig(config *ServeConfig) error {
	if config.cancel != nil {
		config.cancel()
	}

	if config.listener != nil {
		if err := config.listener.Close(); err != nil {
			log.Warnf("Error closing listener for port %d: %v", config.Port, err)
		}
	}

	config.Active = false
	log.Infof("Stopped serving on port %d", config.Port)
	return nil
}

// startHTTP starts an HTTP reverse proxy
func (m *Manager) startHTTP(ctx context.Context, config *ServeConfig, targetURL *url.URL) error {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	server := &http.Server{
		Addr:    config.ListenAddress,
		Handler: proxy,
	}

	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", config.ListenAddress, err)
	}

	config.listener = listener
	config.server = server

	// Start server in background
	go func() {
		defer func() {
			m.mu.Lock()
			config.Active = false
			m.mu.Unlock()
		}()

		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTP server error on port %d: %v", config.Port, err)
		}
	}()

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	return nil
}

// startHTTPS starts an HTTPS reverse proxy with self-signed certificate
func (m *Manager) startHTTPS(ctx context.Context, config *ServeConfig, targetURL *url.URL) error {
	// Generate self-signed certificate
	cert, err := m.generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate self-signed certificate: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	server := &http.Server{
		Addr:    config.ListenAddress,
		Handler: proxy,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", config.ListenAddress, err)
	}

	tlsListener := tls.NewListener(listener, server.TLSConfig)
	config.listener = tlsListener
	config.server = server

	// Start server in background
	go func() {
		defer func() {
			m.mu.Lock()
			config.Active = false
			m.mu.Unlock()
		}()

		if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTPS server error on port %d: %v", config.Port, err)
		}
	}()

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	return nil
}

// startTCP starts a TCP proxy
func (m *Manager) startTCP(ctx context.Context, config *ServeConfig, target string) error {
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", config.ListenAddress, err)
	}

	config.listener = listener

	// Start accepting connections in background
	go func() {
		defer func() {
			m.mu.Lock()
			config.Active = false
			m.mu.Unlock()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return // Normal shutdown
				default:
					log.Errorf("TCP listener error on port %d: %v", config.Port, err)
					return
				}
			}

			// Handle connection in background
			go m.handleTCPConnection(ctx, conn, target)
		}
	}()

	return nil
}

// handleTCPConnection handles a single TCP connection
func (m *Manager) handleTCPConnection(ctx context.Context, clientConn net.Conn, target string) {
	defer clientConn.Close()

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Errorf("Failed to connect to target %s: %v", target, err)
		return
	}
	defer targetConn.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()

	// Wait for either direction to finish or context to be canceled
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// generateSelfSignedCert generates a self-signed TLS certificate
func (m *Manager) generateSelfSignedCert() (tls.Certificate, error) {
	// Generate private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"NetBird Serve"},
			CommonName:   m.netbirdIP,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP(m.netbirdIP)},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create TLS certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}

	return cert, nil
}

// UpdateNetBirdIP updates the NetBird interface IP
func (m *Manager) UpdateNetBirdIP(newIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.netbirdIP = newIP
	log.Infof("Updated NetBird IP to %s", newIP)
}
package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	servePort     uint32
	serveProtocol string
	serveAll      bool
)

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.AddCommand(serveStartCmd)
	serveCmd.AddCommand(serveStopCmd)
	serveCmd.AddCommand(serveStatusCmd)

	serveStartCmd.Flags().Uint32Var(&servePort, "port", 0, "Port to listen on (required)")
	serveStartCmd.Flags().StringVar(&serveProtocol, "proto", "http", "Protocol: http, https, or tcp")
	_ = serveStartCmd.MarkFlagRequired("port")

	serveStopCmd.Flags().Uint32Var(&servePort, "port", 0, "Port to stop serving")
	serveStopCmd.Flags().BoolVar(&serveAll, "all", false, "Stop all serve configurations")
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Expose local services to the NetBird network",
	Long:  `Manage local service exposure to other peers on the NetBird network.`,
}

var serveStartCmd = &cobra.Command{
	Use:     "start <target>",
	Short:   "Start serving a local service",
	Long:    `Start exposing a local service to the NetBird network.`,
	Example: `  netbird serve start localhost:3000 --port 443 --proto https
  netbird serve start 127.0.0.1:8080 --port 80 --proto http
  netbird serve start localhost:5432 --port 5432 --proto tcp`,
	Args: cobra.ExactArgs(1),
	RunE: serveStartRun,
}

var serveStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop serving",
	Long:  `Stop exposing a local service.`,
	Example: `  netbird serve stop --port 443
  netbird serve stop --all`,
	RunE: serveStopRun,
}

var serveStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show serve status",
	Long:  `Show the status of all active serve configurations.`,
	RunE:  serveStatusRun,
}

// serveState tracks active serve configurations (in-process, no daemon needed for MVP)
type serveEntry struct {
	Target   string
	Port     uint32
	Protocol string
	listener net.Listener
	cancel   context.CancelFunc
}

var (
	activeServes   = make(map[uint32]*serveEntry)
	activeServesMu sync.Mutex
)

func getNetBirdIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Name == "wt0" || iface.Name == "utun100" || iface.Name == "netbird" {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					return ipnet.IP.String(), nil
				}
			}
		}
	}

	// Fallback: look for 100.x.y.z addresses on any interface
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP.To4()
				if ip != nil && ip[0] == 100 && ip[1] >= 64 {
					return ip.String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("NetBird interface not found. Is NetBird running?")
}

func generateSelfSignedCert(ip string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: ip,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP(ip)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func startHTTPServe(ctx context.Context, listenAddr, target string, port uint32, useTLS bool) (net.Listener, error) {
	targetURL, err := url.Parse(fmt.Sprintf("http://%s", target))
	if err != nil {
		return nil, fmt.Errorf("invalid target: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	server := &http.Server{
		Handler: proxy,
	}

	var listener net.Listener

	if useTLS {
		cert, err := generateSelfSignedCert(listenAddr[:len(listenAddr)-len(fmt.Sprintf(":%d", port))])
		if err != nil {
			return nil, fmt.Errorf("failed to generate TLS certificate: %v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		listener, err = tls.Listen("tcp", listenAddr, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to start TLS listener: %v", err)
		}
	} else {
		listener, err = net.Listen("tcp", listenAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to start listener: %v", err)
		}
	}

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Errorf("serve error: %v", err)
		}
	}()

	return listener, nil
}

func startTCPServe(ctx context.Context, listenAddr, target string) (net.Listener, error) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to start TCP listener: %v", err)
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Errorf("accept error: %v", err)
					continue
				}
			}
			go handleTCPConn(conn, target)
		}
	}()

	return listener, nil
}

func handleTCPConn(clientConn net.Conn, target string) {
	defer clientConn.Close()

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Errorf("failed to connect to target %s: %v", target, err)
		return
	}
	defer targetConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()
	<-done
}

func serveStartRun(cmd *cobra.Command, args []string) error {
	target := args[0]

	nbIP, err := getNetBirdIP()
	if err != nil {
		return err
	}

	listenAddr := fmt.Sprintf("%s:%d", nbIP, servePort)

	activeServesMu.Lock()
	if _, exists := activeServes[servePort]; exists {
		activeServesMu.Unlock()
		return fmt.Errorf("port %d is already being served", servePort)
	}
	activeServesMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())

	var listener net.Listener

	switch serveProtocol {
	case "http":
		listener, err = startHTTPServe(ctx, listenAddr, target, servePort, false)
	case "https":
		listener, err = startHTTPServe(ctx, listenAddr, target, servePort, true)
	case "tcp":
		listener, err = startTCPServe(ctx, listenAddr, target)
	default:
		cancel()
		return fmt.Errorf("unsupported protocol: %s (use http, https, or tcp)", serveProtocol)
	}

	if err != nil {
		cancel()
		return err
	}

	entry := &serveEntry{
		Target:   target,
		Port:     servePort,
		Protocol: serveProtocol,
		listener: listener,
		cancel:   cancel,
	}

	activeServesMu.Lock()
	activeServes[servePort] = entry
	activeServesMu.Unlock()

	cmd.Printf("Serving %s://%s → %s\n", serveProtocol, listenAddr, target)
	cmd.Println("Press Ctrl+C to stop.")

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	cancel()
	cmd.Println("\nStopped serving.")
	return nil
}

func serveStopRun(cmd *cobra.Command, _ []string) error {
	activeServesMu.Lock()
	defer activeServesMu.Unlock()

	if serveAll {
		count := len(activeServes)
		for port, entry := range activeServes {
			entry.cancel()
			delete(activeServes, port)
		}
		cmd.Printf("Stopped %d serve configuration(s).\n", count)
		return nil
	}

	if servePort == 0 {
		return fmt.Errorf("specify --port or --all")
	}

	entry, exists := activeServes[servePort]
	if !exists {
		return fmt.Errorf("no serve configuration found for port %d", servePort)
	}

	entry.cancel()
	delete(activeServes, servePort)
	cmd.Printf("Stopped serving on port %d.\n", servePort)
	return nil
}

func serveStatusRun(cmd *cobra.Command, _ []string) error {
	activeServesMu.Lock()
	defer activeServesMu.Unlock()

	if len(activeServes) == 0 {
		cmd.Println("No active serve configurations.")
		return nil
	}

	cmd.Println("Active serve configurations:")
	cmd.Println()
	for _, entry := range activeServes {
		cmd.Printf("  %s://netbird-ip:%d → %s\n", entry.Protocol, entry.Port, entry.Target)
	}
	return nil
}

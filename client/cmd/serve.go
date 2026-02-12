package cmd

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

var (
	serveProtocol string
	servePort     uint32
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Share a local service on the NetBird network",
	Long:  "Commands to expose local services to other NetBird peers",
}

var serveStartCmd = &cobra.Command{
	Use:     "start <target>",
	Aliases: []string{"<target>"},
	Short:   "Start sharing a local service",
	Example: "  netbird serve start localhost:3000 --port 443 --proto https\n  netbird serve start 127.0.0.1:8080 --port 80 --proto http",
	Long:    "Start exposing a local service to the NetBird network. The target should be in the format host:port.",
	Args:    cobra.ExactArgs(1),
	RunE:    serveStart,
}

var serveStopCmd = &cobra.Command{
	Use:     "stop",
	Aliases: []string{"off"},
	Short:   "Stop sharing services",
	Example: "  netbird serve stop --port 443\n  netbird serve stop --all",
	Long:    "Stop exposing services to the NetBird network.",
	RunE:    serveStop,
}

var serveStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show active serve configurations",
	Example: "  netbird serve status",
	Long:    "Show currently active serve configurations and their status.",
	RunE:    serveStatus,
}

func init() {
	serveStartCmd.Flags().Uint32VarP(&servePort, "port", "p", 0, "Port to serve on (required)")
	serveStartCmd.Flags().StringVar(&serveProtocol, "proto", "http", "Protocol to use: http, https, or tcp")
	serveStartCmd.MarkFlagRequired("port")

	serveStopCmd.Flags().Uint32VarP(&servePort, "port", "p", 0, "Port to stop serving on")
	serveStopCmd.Flags().Bool("all", false, "Stop all active serves")

	serveCmd.AddCommand(serveStartCmd)
	serveCmd.AddCommand(serveStopCmd)
	serveCmd.AddCommand(serveStatusCmd)
}

func serveStart(cmd *cobra.Command, args []string) error {
	target := args[0]
	
	// Validate target format
	if !strings.Contains(target, ":") {
		return fmt.Errorf("target must be in format host:port, got: %s", target)
	}
	
	// Validate protocol
	if serveProtocol != "http" && serveProtocol != "https" && serveProtocol != "tcp" {
		return fmt.Errorf("protocol must be one of: http, https, tcp")
	}
	
	// Validate port
	if servePort == 0 {
		return fmt.Errorf("port is required")
	}
	
	// Validate target is reachable
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target format: %v", err)
	}
	
	if _, err := strconv.Atoi(portStr); err != nil {
		return fmt.Errorf("invalid target port: %v", err)
	}
	
	// For localhost/127.0.0.1, no need to check connectivity
	if host != "localhost" && host != "127.0.0.1" {
		conn, err := net.DialTimeout("tcp", target, cmd.Context().Done().Value().(context.Context).Value("timeout").(context.Duration))
		if err == nil {
			conn.Close()
		}
	}

	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	_, err = client.ServeStart(cmd.Context(), &proto.ServeStartRequest{
		Target:   target,
		Port:     servePort,
		Protocol: serveProtocol,
	})
	if err != nil {
		return fmt.Errorf("failed to start serving: %v", status.Convert(err).Message())
	}

	cmd.Printf("Started serving %s on port %d via %s\n", target, servePort, serveProtocol)
	return nil
}

func serveStop(cmd *cobra.Command, args []string) error {
	all, _ := cmd.Flags().GetBool("all")
	
	if !all && servePort == 0 {
		return fmt.Errorf("either --port or --all is required")
	}

	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.ServeStop(cmd.Context(), &proto.ServeStopRequest{
		Port: servePort,
		All:  all,
	})
	if err != nil {
		return fmt.Errorf("failed to stop serving: %v", status.Convert(err).Message())
	}

	if all {
		cmd.Printf("Stopped all active serves (%d configurations)\n", resp.StoppedCount)
	} else {
		cmd.Printf("Stopped serving on port %d\n", servePort)
	}
	return nil
}

func serveStatus(cmd *cobra.Command, args []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.ServeStatus(cmd.Context(), &proto.ServeStatusRequest{})
	if err != nil {
		return fmt.Errorf("failed to get serve status: %v", status.Convert(err).Message())
	}

	if len(resp.GetConfigurations()) == 0 {
		cmd.Println("No active serve configurations.")
		return nil
	}

	printServeConfigurations(cmd, resp.GetConfigurations())
	return nil
}

func printServeConfigurations(cmd *cobra.Command, configs []*proto.ServeConfiguration) {
	cmd.Println("Active serve configurations:")
	cmd.Println()

	for _, config := range configs {
		status := "Running"
		if !config.GetActive() {
			status = "Stopped"
		}
		cmd.Printf("  %s:%d → %s (%s) [%s]\n", 
			config.GetListenAddress(), 
			config.GetPort(), 
			config.GetTarget(), 
			config.GetProtocol(), 
			status)
	}
}
package anytls_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type compatibilityEcho struct{}

func (compatibilityEcho) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	io.Copy(conn, conn)
}

// TestUnmodifiedUpstreamInterop builds a real pinned upstream module without replace.
// It exercises authenticated plaintext protocol integration, not the separate TLS transport.
func TestUnmodifiedUpstreamInterop(t *testing.T) {
	if testing.Short() {
		t.Skip("separate upstream module build")
	}
	dir := t.TempDir()
	source, err := os.ReadFile(filepath.Join("testdata", "upstream", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	module := "module upstream-compat-probe\n\ngo 1.23.1\n\nrequire github.com/anytls/sing-anytls v0.0.11\n"
	if err = os.WriteFile(filepath.Join(dir, "go.mod"), []byte(module), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "main.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "upstream-helper")
	if runtime.GOOS == "windows" {
		helper += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=mod", "-o", helper, ".")
	build.Dir = dir
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "GOWORK=") && !strings.HasPrefix(env, "GOFLAGS=") {
			build.Env = append(build.Env, env)
		}
	}
	build.Env = append(build.Env, "GOWORK=off", "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual upstream: %v\n%s", err, out)
	}

	t.Run("enhanced-client-to-original-server", func(t *testing.T) {
		process := exec.CommandContext(ctx, helper, "server")
		stdout, err := process.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		process.Stderr = &stderr
		if err = process.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
		address, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			t.Fatalf("upstream server: %v %s", err, stderr.String())
		}
		client, err := anytls.NewClient(ctx, anytls.ClientConfig{
			Password: "compat-password", Logger: logger.NOP(), EnhancedPadding: true,
			DialOut: func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimSpace(address))
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		for index := 0; index < 3; index++ {
			conn, err := client.CreateProxy(ctx, M.ParseSocksaddr("example.com:443"))
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte(fmt.Sprintf("enhanced-to-original-%d", index))
			n, err := conn.Write(payload)
			if err != nil || n != len(payload) {
				t.Fatalf("write n=%d err=%v", n, err)
			}
			response := make([]byte, len(payload))
			if _, err = io.ReadFull(conn, response); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, response) {
				t.Fatal("payload mismatch")
			}
			conn.Close()
		}
	})

	t.Run("original-client-to-enhanced-server", func(t *testing.T) {
		server, err := anytls.NewService(anytls.ServiceConfig{
			Users:         []anytls.User{{Name: "test", Password: "compat-password"}},
			PaddingScheme: padding.DefaultPaddingScheme,
			Handler:       compatibilityEcho{}, Logger: logger.NOP(), EnhancedPadding: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go func() { defer conn.Close(); _ = server.NewConnection(ctx, conn, M.Socksaddr{}, nil) }()
			}
		}()
		out, err := exec.CommandContext(ctx, helper, "client", listener.Addr().String()).CombinedOutput()
		if err != nil {
			t.Fatalf("unmodified upstream client: %v\n%s", err, out)
		}
		if !bytes.Contains(out, []byte("PASS original v0.0.11 client")) {
			t.Fatalf("missing upstream proof: %s", out)
		}
	})
}

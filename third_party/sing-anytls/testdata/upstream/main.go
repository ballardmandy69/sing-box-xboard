// This helper is built in a separate module against the unmodified v0.0.11.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type echoHandler struct{}

func (echoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	io.Copy(conn, conn)
}

func main() {
	ctx := context.Background()
	if os.Args[1] == "server" {
		s, err := anytls.NewService(anytls.ServiceConfig{
			Users:         []anytls.User{{Name: "test", Password: "compat-password"}},
			PaddingScheme: padding.DefaultPaddingScheme,
			Handler:       echoHandler{}, Logger: logger.NOP(),
		})
		must(err)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		must(err)
		fmt.Println(listener.Addr().String())
		for {
			conn, err := listener.Accept()
			must(err)
			go func() { defer conn.Close(); _ = s.NewConnection(ctx, conn, M.Socksaddr{}, nil) }()
		}
	}
	client, err := anytls.NewClient(ctx, anytls.ClientConfig{
		Password: "compat-password", Logger: logger.NOP(),
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", os.Args[2])
		},
	})
	must(err)
	defer client.Close()
	for index := 0; index < 3; index++ {
		conn, err := client.CreateProxy(ctx, M.ParseSocksaddr("example.com:443"))
		must(err)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		payload := []byte(fmt.Sprintf("upstream-interop-%d", index))
		_, err = conn.Write(payload)
		must(err)
		response := make([]byte, len(payload))
		_, err = io.ReadFull(conn, response)
		must(err)
		if string(response) != string(payload) {
			panic("payload mismatch")
		}
		conn.Close()
	}
	fmt.Println("PASS original v0.0.11 client")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

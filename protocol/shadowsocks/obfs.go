package shadowsocks

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	SBufio "github.com/sagernet/sing/common/bufio"
)

const obfsResponse = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

type obfsUser struct {
	identity multiUserIdentity
	uuid     string
}

// obfsProcessor implements the original HTTP preamble and preserves following SS ciphertext.
// The Host identifies a candidate; the Shadowsocks service still verifies its encryption key.
// @author lyt
// @date 2026-10-29
type obfsProcessor struct {
	users atomic.Pointer[map[string]obfsUser]
}

func obfsHost(uuid string) string {
	digest := md5.Sum([]byte(uuid))
	return hex.EncodeToString(digest[:]) + ".microsoft.com"
}

func (p *obfsProcessor) update(users []multiUserIdentity, uuids []string) {
	entries := make(map[string]obfsUser, len(users))
	for index, user := range users {
		entries[obfsHost(uuids[index])] = obfsUser{identity: user, uuid: uuids[index]}
	}
	p.users.Store(&entries)
}

func (p *obfsProcessor) process(conn net.Conn) (net.Conn, obfsUser, error) {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return conn, obfsUser{}, fmt.Errorf("set Shadowsocks obfs read deadline: %w", err)
	}
	buffer := buf.NewSize(8192)
	defer buffer.Release()
	if _, err := buffer.ReadOnceFrom(conn); err != nil {
		return conn, obfsUser{}, fmt.Errorf("read Shadowsocks obfs preamble: %w", err)
	}
	headerEnd := bytes.Index(buffer.Bytes(), []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return conn, obfsUser{}, fmt.Errorf("incomplete Shadowsocks obfs preamble")
	}
	headerEnd += 4
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buffer.Bytes()[:headerEnd])))
	if err != nil {
		return conn, obfsUser{}, fmt.Errorf("invalid Shadowsocks obfs preamble")
	}
	// The original internal readRequest keeps Header.Host. The exported function removes it
	// and prefers an absolute URL's authority, so recover the header for absolute-form requests.
	host := request.Host
	if request.URL.Host != "" {
		reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(buffer.Bytes()[:headerEnd])))
		if _, err = reader.ReadLine(); err != nil {
			return conn, obfsUser{}, fmt.Errorf("invalid Shadowsocks obfs request line")
		}
		headers, headerErr := reader.ReadMIMEHeader()
		if headerErr != nil {
			return conn, obfsUser{}, fmt.Errorf("invalid Shadowsocks obfs headers")
		}
		host = headers.Get("Host")
	}
	host = strings.Split(host, ":")[0]
	users := p.users.Load()
	if host == "" || users == nil {
		return conn, obfsUser{}, fmt.Errorf("unknown Shadowsocks obfs user")
	}
	user, loaded := (*users)[host]
	if !loaded || user.uuid == "" {
		return conn, obfsUser{}, fmt.Errorf("unknown Shadowsocks obfs user")
	}
	if written, err := io.WriteString(conn, obfsResponse); err != nil {
		return conn, obfsUser{}, fmt.Errorf("write Shadowsocks obfs response: %w", err)
	} else if written != len(obfsResponse) {
		return conn, obfsUser{}, io.ErrShortWrite
	}
	// As in the original handler, clearing the deadline is best effort after the response.
	_ = conn.SetReadDeadline(time.Time{})
	buffer.Advance(headerEnd)
	if !buffer.IsEmpty() {
		conn = SBufio.NewCachedConn(conn, buffer)
	}
	return conn, user, nil
}

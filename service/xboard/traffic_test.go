package xboard

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/ssmapi"
)

// trafficFixtureConn supplies application bytes to the actual accounting wrapper.
// @author lyt
// @date 2026-10-29
type trafficFixtureConn struct {
	net.Conn
	reader io.Reader
}

func (c *trafficFixtureConn) Read(buffer []byte) (int, error)  { return c.reader.Read(buffer) }
func (c *trafficFixtureConn) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (c *trafficFixtureConn) Close() error                     { return nil }

func addFixtureTraffic(t *testing.T, n *node, up, down int) {
	t.Helper()
	connection := n.traffic.TrackConnection(&trafficFixtureConn{
		reader: strings.NewReader(strings.Repeat("u", up)),
	}, adapter.InboundContext{User: "alice"})
	if _, err := io.ReadFull(connection, make([]byte, up)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(make([]byte, down)); err != nil {
		t.Fatal(err)
	}
	connection.Close()
}

func trafficTestNode(server *httptest.Server) *node {
	return &node{
		service: &Service{}, traffic: ssmapi.NewTrafficManager(),
		primary: fixturePanel(server, "test", "test-token"), nodeID: 1, nodeType: "anytls",
		trafficFactor: 1, users: map[string]uint64{"alice": 101},
	}
}

func fixturePanel(server *httptest.Server, tag, token string) *nodePanel {
	return &nodePanel{client: &panelClient{client: server.Client(), options: option.XBoardPanelOptions{
		PanelTag: tag, APIHost: server.URL, APIKey: token, NodeID: 1, NodeType: "anytls",
	}}}
}

func TestTrafficReportRetainsBytesUntilSuccess(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusNotModified} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var requests atomic.Int32
			var received [2]int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload map[string][2]int64
				if json.NewDecoder(r.Body).Decode(&payload) != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				received = payload["101"]
				if requests.Add(1) == 1 {
					w.WriteHeader(status)
				}
			}))
			defer server.Close()
			n := trafficTestNode(server)
			n.trafficFactor = 0.5
			addFixtureTraffic(t, n, 3, 4)
			if err := n.pushTraffic(context.Background()); err == nil {
				t.Fatal("failed report was accepted")
			}
			if received != [2]int64{2, 2} {
				t.Fatalf("traffic factor must round each direction upward: %v", received)
			}
			addFixtureTraffic(t, n, 1, 1)
			if err := n.pushTraffic(context.Background()); err != nil {
				t.Fatal(err)
			}
			if received != [2]int64{2, 3} {
				t.Fatalf("failed report lost raw bytes or compounded the factor: %v", received)
			}
			if err := n.pushTraffic(context.Background()); err != nil || requests.Load() != 2 {
				t.Fatal("successful report was sent again")
			}
		})
	}
}

func TestTrafficReportPreservesBytesArrivingDuringRequest(t *testing.T) {
	var n *node
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addFixtureTraffic(t, n, 5, 7)
	}))
	defer server.Close()
	n = trafficTestNode(server)
	addFixtureTraffic(t, n, 3, 4)
	if err := n.pushTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	remaining := n.traffic.SnapshotTraffic([]string{"alice"})[0]
	if remaining.UplinkBytes != 5 || remaining.DownlinkBytes != 7 {
		t.Fatal("successful report cleared bytes arriving after its snapshot")
	}
}

func TestDisableUploadTrafficSuppressesEntireReport(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	n := trafficTestNode(server)
	n.disableUpload = true
	addFixtureTraffic(t, n, 3, 4)
	if err := n.pushTraffic(context.Background()); err != nil || requests.Load() != 0 {
		t.Fatal("DisableUploadTraffic must suppress the entire report")
	}
	remaining := n.traffic.SnapshotTraffic([]string{"alice"})[0]
	if remaining.UplinkBytes != 3 || remaining.DownlinkBytes != 4 {
		t.Fatal("disabled reporting consumed statistics")
	}
}

func TestTrafficReportAcknowledgesSuccessfulStatusRange(t *testing.T) {
	for _, status := range []int{http.StatusCreated, http.StatusAccepted, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()
			n := trafficTestNode(server)
			addFixtureTraffic(t, n, 3, 4)
			if err := n.pushTraffic(context.Background()); err != nil {
				t.Fatal(err)
			}
			remaining := n.traffic.SnapshotTraffic([]string{"alice"})[0]
			if remaining.UplinkBytes != 0 || remaining.DownlinkBytes != 0 {
				t.Fatal("successful response did not acknowledge its raw-byte snapshot")
			}
		})
	}
}

func TestConcurrentTrafficReportsDoNotDoubleDebit(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	n := trafficTestNode(server)
	addFixtureTraffic(t, n, 3, 4)
	var workers sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		workers.Go(func() { errors <- n.pushTraffic(context.Background()) })
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatal("concurrent report transactions duplicated the same snapshot")
	}
}

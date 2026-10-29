package xboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestIllegalReportRetainsFailuresAndSerializesProducers(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	received := make(chan []panelIllegalRecord, 4)
	var calls atomic.Int32
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mod_mu/users/detectlog" || r.Method != http.MethodPost {
			t.Error("unexpected violation request")
		}
		var body struct {
			Data []panelIllegalRecord `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		received <- body.Data
		switch calls.Add(1) {
		case 1:
			fmt.Fprint(w, `{"ret":0}`)
			return
		case 2:
			close(entered)
			<-release
		}
		fmt.Fprint(w, `{"ret":1}`)
	}))
	defer panel.Close()
	options := panelTestOptions()
	options.PanelType, options.APIHost = "sspanel", panel.URL
	client, err := newPanelClient(options)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{primary: &nodePanel{client: client}, disableUpload: true}
	n.recordIllegal(42, 7)
	n.recordIllegal(42, 7)
	want := []panelIllegalRecord{{UserID: 42, RuleID: 7}, {UserID: 42, RuleID: 7}}
	if err := n.pushIllegal(context.Background()); err == nil {
		t.Fatal("failed report was acknowledged")
	}
	if got := <-received; !reflect.DeepEqual(got, want) {
		t.Fatal("original queue must preserve repeated violations")
	}
	pushResult := make(chan error, 1)
	go func() { pushResult <- n.pushIllegal(context.Background()) }()
	<-entered
	if got := <-received; !reflect.DeepEqual(got, want) {
		t.Fatal("retry lost the retained batch")
	}
	started, added := make(chan struct{}), make(chan struct{})
	go func() { close(started); n.recordIllegal(43, 8); close(added) }()
	<-started
	select {
	case <-added:
		close(release)
		t.Fatal("producer must wait for the original locked HTTP upload")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-pushResult; err != nil {
		t.Fatal(err)
	}
	<-added
	if err := n.pushIllegal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := <-received; !reflect.DeepEqual(got, []panelIllegalRecord{{UserID: 43, RuleID: 8}}) {
		t.Fatal("successful report cleared a waiting producer's later violation")
	}
	if err := n.pushIllegal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got == nil || len(got) != 0 {
		t.Fatal("empty violation queue must be an empty JSON array")
	}
	n.panels = []*nodePanel{n.primary}
	n.recordIllegal(44, 9)
	if err := n.pushIllegal(context.Background()); err != nil || calls.Load() != 4 || len(n.illegal) != 0 {
		t.Fatal("multi's no-op report should acknowledge its batch without HTTP")
	}
}

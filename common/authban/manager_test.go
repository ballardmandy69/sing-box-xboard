package authban

import (
	"fmt"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestFailureAndBanExpireAtUnixSecondWithoutReadRenewal(t *testing.T) {
	now := time.Unix(100, 900_000_000)
	m := New()
	m.now = func() time.Time { return now }
	source := M.ParseSocksaddr("192.0.2.1:1000")
	m.ReportFailure(source)
	now = time.Unix(159, 999_999_999)
	m.ReportFailure(M.ParseSocksaddr("192.0.2.1:2000"))
	if m.IsBlocked(source) {
		t.Fatal("two failures must not block, regardless of source port")
	}
	now = time.Unix(218, 0)
	m.ReportFailure(source)
	if !m.IsBlocked(source) {
		t.Fatal("third failure in the sliding lifetime did not block")
	}
	if m.IsBlocked(M.ParseSocksaddr("192.0.2.2:1000")) {
		t.Fatal("different source inherited the ban")
	}
	now = time.Unix(277, 999_999_999)
	if !m.IsBlocked(source) {
		t.Fatal("ban expired before its integer second boundary")
	}
	m.ReportFailure(source)
	now = time.Unix(278, 0)
	if m.IsBlocked(source) {
		t.Fatal("query or rejected attempt renewed the ban")
	}
	m.ReportFailure(source)
	if m.entries[sourceKey(source)].Value.(*failureEntry).count != 1 {
		t.Fatal("expired failure count was retained after the ban ended")
	}
}

func TestExpiredCounterRestartsAndStoreCleansOldSources(t *testing.T) {
	now := time.Unix(10, 0)
	m := New()
	m.now = func() time.Time { return now }
	for index := 0; index < 1000; index++ {
		m.ReportFailure(M.Socksaddr{Fqdn: fmt.Sprintf("source-%d.test", index)})
	}
	now = time.Unix(70, 0)
	source := M.Socksaddr{Fqdn: "source-0.test", Port: 5000}
	m.ReportFailure(source)
	if len(m.entries) != 1 || m.ages.Len() != 1 {
		t.Fatal("store failed to lazily remove expired sources")
	}
	if m.entries[sourceKey(source)].Value.(*failureEntry).count != 1 {
		t.Fatal("a counter at expires == now did not restart")
	}
	m.ReportFailure(M.Socksaddr{Fqdn: "source-0.test", Port: 6000})
	m.ReportFailure(source)
	if !m.IsBlocked(source) || m.IsBlocked(M.Socksaddr{Fqdn: "SOURCE-0.test"}) {
		t.Fatal("source FQDN must retain its original spelling and omit the port")
	}
}

func TestConcurrentFailureCountingAndReads(t *testing.T) {
	m := New()
	m.now = func() time.Time { return time.Unix(1000, 0) }
	var wait sync.WaitGroup
	for index := 0; index < 100; index++ {
		source := M.Socksaddr{Fqdn: fmt.Sprintf("concurrent-%d.test", index)}
		for attempt := 0; attempt < 3; attempt++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				m.ReportFailure(source)
				_ = m.IsBlocked(source)
			}()
		}
	}
	wait.Wait()
	for index := 0; index < 100; index++ {
		if !m.IsBlocked(M.Socksaddr{Fqdn: fmt.Sprintf("concurrent-%d.test", index)}) {
			t.Fatal("concurrent failures lost an increment")
		}
	}
}

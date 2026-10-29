// Package authban implements the shared source policy for repeated unknown-user authentication.
package authban

import (
	"container/list"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const lifetimeSeconds int64 = 60

var shared = New()

// Manager tracks failures by source IP (or source FQDN), independently of ports and users.
// @author lyt
// @date 2026-10-29
type Manager struct {
	access  sync.Mutex
	entries map[string]*list.Element
	ages    list.List
	now     func() time.Time
}

type failureEntry struct {
	key     string
	count   uint16
	expires int64
}

func New() *Manager {
	return &Manager{entries: make(map[string]*list.Element), now: time.Now}
}

// Shared returns the single process-wide policy used by enabled protocol inbounds.
func Shared() *Manager { return shared }

func sourceKey(source M.Socksaddr) string {
	if source.Fqdn != "" {
		return source.Fqdn
	}
	return source.Addr.String()
}

func (m *Manager) IsBlocked(source M.Socksaddr) bool {
	m.access.Lock()
	defer m.access.Unlock()
	element := m.load(sourceKey(source), m.now().Unix())
	return element != nil && element.Value.(*failureEntry).count >= 3
}

func (m *Manager) ReportFailure(source M.Socksaddr) {
	m.access.Lock()
	defer m.access.Unlock()
	now := m.now().Unix()
	key := sourceKey(source)
	element := m.load(key, now)
	if element == nil {
		element = m.ages.PushBack(&failureEntry{key: key})
		m.entries[key] = element
	}
	entry := element.Value.(*failureEntry)
	if entry.count >= 3 {
		return
	}
	entry.count++
	entry.expires = now + lifetimeSeconds
	m.ages.MoveToBack(element)
	// Failure and ban expirations coincide on the third failure. A single record preserves
	// both lifetimes, while the lock prevents the sample's concurrent lost increments.
	for oldest := m.ages.Front(); oldest != nil; oldest = m.ages.Front() {
		if oldest.Value.(*failureEntry).expires > now {
			break
		}
		m.remove(oldest)
	}
}

func (m *Manager) load(key string, now int64) *list.Element {
	element := m.entries[key]
	if element != nil && element.Value.(*failureEntry).expires <= now {
		m.remove(element)
		return nil
	}
	return element
}

func (m *Manager) remove(element *list.Element) {
	delete(m.entries, element.Value.(*failureEntry).key)
	m.ages.Remove(element)
}

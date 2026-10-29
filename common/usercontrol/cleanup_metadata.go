package usercontrol

import (
	"net"
	"reflect"
)

// UpdateMetadata changes an existing registration after the managed routing gate accepts it.
// It never creates a new counter wrapper or substitutes a protocol credential for the user label.
func (c *ConnectionCleaner) UpdateMetadata(conn net.Conn, kind, source, userLabel string) {
	key := connectionKey(conn)
	if wrapper, ok := conn.(*cleanupConn); ok {
		key = wrapper.key
	} else if !reflect.TypeOf(key).Comparable() {
		return
	}
	c.access.Lock()
	if tracked := c.entries[key]; tracked != nil {
		tracked.kind, tracked.source, tracked.userLabel = kind, source, userLabel
	}
	c.access.Unlock()
}

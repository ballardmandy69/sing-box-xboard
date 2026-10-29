package usercontrol

import (
	"net"
	"net/netip"
	"slices"
	"strings"
)

// SourceUsage summarizes unique registered closer keys by their retained source IP.
// @author lyt
// @date 2026-10-29
type SourceUsage struct {
	SourceIP string
	Count    int
	Traffic  int64
}

// TrackAcceptedConnection is called before the protocol handler reads its first byte.
func (c *ConnectionCleaner) TrackAcceptedConnection(conn net.Conn, source netip.Addr) net.Conn {
	tracked := c.trackConnection(conn, source.Unmap().String()).(*cleanupConn)
	c.access.Lock()
	tracked.kind = "tcp-inbound"
	tracked.source = source.Unmap().String()
	tracked.userLabel = ""
	c.access.Unlock()
	return tracked
}

// SourceSnapshot orders sources by connection count, traffic, then textual IP address.
func (c *ConnectionCleaner) SourceSnapshot() []SourceUsage {
	c.access.Lock()
	groups := make(map[string]SourceUsage)
	for _, conn := range c.entries {
		if conn.source == "" {
			continue
		}
		entry := groups[conn.source]
		entry.SourceIP = conn.source
		entry.Count++
		entry.Traffic += conn.activity.Load()
		groups[conn.source] = entry
	}
	c.access.Unlock()
	result := make([]SourceUsage, 0, len(groups))
	for _, entry := range groups {
		result = append(result, entry)
	}
	slices.SortFunc(result, func(left, right SourceUsage) int {
		if left.Count != right.Count {
			if left.Count > right.Count {
				return -1
			}
			return 1
		}
		if left.Traffic != right.Traffic {
			if left.Traffic > right.Traffic {
				return -1
			}
			return 1
		}
		return strings.Compare(left.SourceIP, right.SourceIP)
	})
	return result
}

// CloseSources closes a snapshot outside the registry lock, allowing Close to unregister safely.
func (c *ConnectionCleaner) CloseSources(sources []string) int {
	selected := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		selected[source] = struct{}{}
	}
	c.access.Lock()
	var connections []*cleanupConn
	for _, conn := range c.entries {
		if _, exists := selected[conn.source]; exists {
			connections = append(connections, conn)
		}
	}
	c.access.Unlock()
	for _, conn := range connections {
		forceClose(conn.Conn)
		conn.Close()
	}
	return len(connections)
}

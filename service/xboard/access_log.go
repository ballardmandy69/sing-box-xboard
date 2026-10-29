package xboard

import (
	"context"
	"errors"
	stdlog "log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

// accessLogQueue preserves the original mode and snapshot-before-upload behavior.
// @author lyt
// @date 2026-10-29
type accessLogQueue struct {
	mode    uint8
	client  *accessLogClient
	access  sync.Mutex
	records []accessRecord
	print   func(...any)
	wait    func(context.Context, time.Duration) error
}

func newAccessLogQueue(mode uint8, client *accessLogClient) *accessLogQueue {
	return &accessLogQueue{mode: mode, client: client, print: stdlog.Println, wait: waitAccessLogRetry}
}

func (q *accessLogQueue) put(record accessRecord) {
	if q.mode == 2 {
		return
	}
	if q.mode == 1 {
		// The original print value omits Time; the wire value includes Unix seconds.
		q.print("[Access]", struct {
			Inbound, Outbound       string
			Uid                     uint64
			Net, Protocol, Src, Dst string
		}{record.Inbound, record.Outbound, record.Uid, record.Net, record.Protocol, record.Src, record.Dst})
	}
	record.Time = time.Now().Unix()
	q.access.Lock()
	q.records = append(q.records, record)
	q.access.Unlock()
}

func (q *accessLogQueue) upload(ctx context.Context) error {
	q.access.Lock()
	records := q.records
	q.records = nil
	q.access.Unlock()
	if len(records) == 0 || q.client == nil {
		return nil
	}
	var err error
	for attempt := range 4 {
		if err = q.client.upload(ctx, records); err == nil {
			return nil
		}
		if attempt < 3 {
			if waitErr := q.wait(ctx, time.Second<<attempt); waitErr != nil {
				return waitErr
			}
		}
	}
	return errors.Join(errors.New("SbApi access-log batch discarded after four failed attempts"), err)
}

func waitAccessLogRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (n *node) accessLogLoop(ctx context.Context, interval time.Duration) {
	for waitAccessLogRetry(ctx, interval) == nil {
		if err := n.accessLog.upload(ctx); err != nil && ctx.Err() == nil {
			n.service.logger.Error("xboard access-log upload: ", err)
		}
	}
}

// accessLogTracker records authenticated streams after routing and before dialing.
// @author lyt
// @date 2026-10-29
type accessLogTracker struct {
	queues map[string]*accessLogQueue
	policy *nodepolicy.Registry
}

func (t *accessLogTracker) record(metadata adapter.InboundContext, outbound adapter.Outbound) {
	panelTag, uid, bound := metadata.ManagedNodeIdentity()
	if !bound {
		panelTag = metadata.Inbound
	}
	if !bound && t.policy != nil {
		panelTag = t.policy.PanelTag(panelTag)
	}
	queue := t.queues[panelTag]
	if queue == nil || queue.mode == 2 || outbound == nil || metadata.Network != N.NetworkTCP {
		return
	}
	if !bound && t.policy != nil && t.policy.HasNode(metadata.Inbound) {
		user, exists := t.policy.LookupUser(metadata.Inbound, metadata.User)
		if !exists {
			return
		}
		uid = user.ID
	} else if !bound {
		name, _, ok := strings.Cut(metadata.User, "@")
		if !ok {
			return
		}
		var err error
		uid, err = strconv.ParseUint(name, 10, 64)
		if err != nil {
			return
		}
	}
	queue.put(accessRecord{
		Inbound: metadata.Inbound, Outbound: outbound.Tag(), Uid: uid, Net: metadata.Network,
		Protocol: metadata.Protocol, Src: metadata.Source.String(), Dst: metadata.Destination.String(),
	})
}

func (t *accessLogTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext,
	_ adapter.Rule, outbound adapter.Outbound,
) net.Conn {
	t.record(metadata, outbound)
	return conn
}

func (*accessLogTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) N.PacketConn {
	return conn
}

func (t *accessLogTracker) RoutedFlow(_ context.Context, metadata adapter.InboundContext,
	_ adapter.Rule, outbound adapter.Outbound,
) tun.FlowTracker {
	t.record(metadata, outbound)
	return nil
}

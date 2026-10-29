package route

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const legacySniffBufferSize = 8192

// applyLegacyInboundOptions runs the original pre-rule sniff and domain strategy stages.
func (r *Router) applyLegacyInboundOptions(ctx context.Context, metadata *adapter.InboundContext, conn net.Conn) (
	originalIP netip.Addr, buffer *buf.Buffer, err error,
) {
	options := metadata.LegacyInboundOptions
	if metadata.Network != N.NetworkTCP {
		return
	}
	if options.SniffEnabled {
		if conn != nil {
			timeout := time.Duration(options.SniffTimeout)
			if timeout == 0 {
				timeout = 500 * time.Millisecond
			}
			buffer = buf.NewSize(legacySniffBufferSize)
			var sniffMetadata adapter.InboundContext
			sniffErr := sniff.PeekStream(ctx, &sniffMetadata, conn, nil, buffer, timeout,
				sniff.TLSClientHello, sniff.BitTorrent, legacyJSONRPC, sniff.HTTPHost)
			metadata.SnifferNames = []string{C.ProtocolTLS, C.ProtocolBitTorrent, "jsonrpc", C.ProtocolHTTP}
			metadata.SniffError = sniffErr
			if sniffErr == nil {
				metadata.Protocol = sniffMetadata.Protocol
				metadata.Domain = sniffMetadata.Domain
				metadata.Client = sniffMetadata.Client
				metadata.TLSFingerprint = sniffMetadata.TLSFingerprint
				if options.SniffOverrideDestination && metadata.Destination.IsIP() &&
					!metadata.FakeIP && M.IsDomainName(metadata.Domain) {
					originalIP = metadata.Destination.Addr
					metadata.Destination = M.Socksaddr{Fqdn: metadata.Domain, Port: metadata.Destination.Port}
				}
				r.logger.DebugContext(ctx, "legacy inbound sniff: protocol=", metadata.Protocol, ", domain=", metadata.Domain)
			} else {
				r.logger.DebugContext(ctx, "legacy inbound sniff: ", sniffErr)
			}
			if buffer.IsEmpty() {
				buffer.Release()
				buffer = nil
			}
		}
		r.applyReverseMapping(ctx, metadata)
	}
	if options.DomainStrategy == 0 || !metadata.Destination.IsDomain() {
		return
	}
	addresses, lookupErr := r.dns.Lookup(adapter.WithContext(ctx, metadata), metadata.Destination.Fqdn,
		adapter.DNSQueryOptions{Strategy: C.DomainStrategy(options.DomainStrategy)})
	if lookupErr != nil {
		if len(metadata.DestinationAddresses) == 0 {
			err = E.Cause(lookupErr, "legacy inbound domain_strategy: resolve ", metadata.Destination.Fqdn)
			return
		}
		r.logger.DebugContext(ctx, "legacy inbound domain_strategy: retain existing addresses after lookup failure: ", lookupErr)
		return
	}
	metadata.DestinationAddresses = addresses
	r.logger.DebugContext(ctx, "legacy inbound domain_strategy: resolved ", metadata.Destination.Fqdn, " to ", addresses)
	return
}

func legacyJSONRPC(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	payload, err := io.ReadAll(io.LimitReader(reader, legacySniffBufferSize))
	if err != nil {
		return err
	}
	if len(payload) < 20 || !bytes.Contains(payload, []byte(`"method"`)) ||
		!bytes.Contains(payload, []byte{'{'}) || !bytes.Contains(payload, []byte{':'}) ||
		(!bytes.Contains(payload, []byte(`"jsonrpc"`)) && !bytes.Contains(payload, []byte(`"id"`))) {
		return E.New("not legacy jsonrpc")
	}
	metadata.Protocol = "jsonrpc"
	return nil
}

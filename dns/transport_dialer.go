package dns

import (
	"context"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func NewLocalDialer(ctx context.Context, options option.LocalDNSServerOptions) (N.Dialer, error) {
	return dialer.NewWithOptions(dialer.Options{
		Context:                 ctx,
		Options:                 options.DialerOptions,
		DirectResolver:          true,
		DefaultOutbound:         legacyDefaultOutbound(ctx),
		DisableEmptyDirectCheck: legacyDefaultOutbound(ctx),
	})
}

func NewRemoteDialer(ctx context.Context, options option.RemoteDNSServerOptions) (N.Dialer, error) {
	if legacyDefaultOutbound(ctx) && options.ServerIsDomain() && options.DomainResolver != nil {
		var err error
		ctx, err = legacyBootstrapContext(ctx)
		if err != nil {
			return nil, err
		}
	}
	return dialer.NewWithOptions(dialer.Options{
		Context:                 ctx,
		Options:                 options.DialerOptions,
		RemoteIsDomain:          options.ServerIsDomain(),
		DirectResolver:          true,
		DefaultOutbound:         legacyDefaultOutbound(ctx),
		DisableEmptyDirectCheck: legacyDefaultOutbound(ctx),
	})
}

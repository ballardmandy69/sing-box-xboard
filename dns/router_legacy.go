package dns

import (
	"context"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
	"net/netip"
)

func legacyBootstrapContext(ctx context.Context) (context.Context, error) {
	router, ok := service.FromContext[adapter.DNSRouter](ctx).(*Router)
	if !ok {
		return nil, E.New("legacy address_resolver requires DNS router")
	}
	// Clone the service registry so this private bootstrap adapter cannot replace the application's router.
	return service.ContextWith[adapter.DNSRouter](service.ExtendContext(ctx), &legacyBootstrapRouter{
		DNSRouter: router, client: router.client,
	}), nil
}

// legacyBootstrapRouter preserves the raw address_strategy passed to the original DNS client.
// @author lyt
// @date 2026-10-29
type legacyBootstrapRouter struct {
	adapter.DNSRouter
	client adapter.DNSClient
}

func (r *legacyBootstrapRouter) Lookup(ctx context.Context, domain string,
	options adapter.DNSQueryOptions,
) ([]netip.Addr, error) {
	if options.Transport == nil {
		return nil, E.New("legacy address resolver transport is missing")
	}
	return r.client.Lookup(ctx, options.Transport, domain, options, nil)
}

// Legacy address servers retain the pre-response-rule evaluator, including query_type rules.
func (r *Router) resolveLegacyServerRuleMode(router adapter.Router,
	overrides map[string]adapter.RuleSetMetadata,
) (bool, dnsRuleModeFlags, error) {
	if !r.legacyServerConfig {
		return resolveLegacyDNSMode(router, r.rawRules, overrides)
	}
	if legacyRulesNeedResponseEvaluator(r.rawRules) {
		if len(r.legacyServerStrategies) > 0 {
			return false, dnsRuleModeFlags{}, E.New("legacy DNS server strategy conflicts with response rules")
		}
		return resolveLegacyDNSMode(router, r.rawRules, overrides)
	}
	flags, err := dnsRuleModeRequirements(router, r.rawRules, overrides)
	return true, flags, err
}

func legacyRulesNeedResponseEvaluator(rules []option.DNSRule) bool {
	for _, rule := range rules {
		var action option.DNSRuleAction
		if rule.Type == C.RuleTypeLogical {
			action = rule.LogicalOptions.DNSRuleAction
			if legacyRulesNeedResponseEvaluator(rule.LogicalOptions.Rules) {
				return true
			}
		} else {
			action = rule.DefaultOptions.DNSRuleAction
			if rule.DefaultOptions.MatchResponse.IsEnabled() || hasResponseMatchFields(rule.DefaultOptions) {
				return true
			}
		}
		if action.Race || action.Action == C.RuleActionTypeEvaluate || action.Action == C.RuleActionTypeRespond {
			return true
		}
	}
	return false
}

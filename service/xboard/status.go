package xboard

import (
	"context"
	"fmt"
	"net/http"
)

// panelStatusReporter identifies providers with a node-status endpoint.
// @author lyt
// @date 2026-10-29
type panelStatusReporter interface {
	reportStatus(context.Context, *panelClient) error
}

func (n *node) pushStatus(ctx context.Context) error {
	// The original multi-provider ReportNodeStatus returns nil without forwarding.
	if n.panels != nil {
		return nil
	}
	reporter, ok := n.primary.client.provider.(panelStatusReporter)
	if !ok {
		return nil
	}
	return reporter.reportStatus(ctx, n.primary.client)
}

func (provider ppanelProvider) reportStatus(ctx context.Context, client *panelClient) error {
	// 132853e-132854f supplies these compatibility constants, not measured machine utilization.
	body := []byte(`{"cpu":100,"mem":100,"disk":100}`)
	_, status, _, err := provider.request(ctx, client, http.MethodPost, "status", "", body)
	if err != nil {
		return err
	}
	if !successfulStatus(status) {
		return fmt.Errorf("unexpected PPanel status report HTTP status: %d", status)
	}
	return nil
}

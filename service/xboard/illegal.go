package xboard

import "context"

// panelIllegalRecord is the original SSPanel rule-violation wire record.
// @author lyt
// @date 2026-10-29
type panelIllegalRecord struct {
	UserID uint64 `json:"user_id"`
	RuleID int    `json:"list_id"`
}

func (n *node) recordIllegal(uid uint64, ruleID int) {
	n.illegalAccess.Lock()
	defer n.illegalAccess.Unlock()
	n.illegal = append(n.illegal, panelIllegalRecord{UserID: uid, RuleID: ruleID})
}

func (n *node) pushIllegal(ctx context.Context) error {
	n.illegalAccess.Lock()
	defer n.illegalAccess.Unlock()
	// Original upload holds the same queue lock through HTTP. Failures retain the whole batch;
	// waiting producers append only after the completed upload has released this lock.
	if n.panels == nil && n.primary != nil && n.primary.client != nil {
		if reporter, ok := n.primary.client.provider.(interface {
			reportIllegal(context.Context, *panelClient, []panelIllegalRecord) error
		}); ok {
			if err := reporter.reportIllegal(ctx, n.primary.client, n.illegal); err != nil {
				return err
			}
		}
	}
	// Other providers, including multi, have an acknowledged no-op report method.
	n.illegal = []panelIllegalRecord{}
	return nil
}

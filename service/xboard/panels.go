package xboard

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// nodePanel owns a source's last successful user response independently of other panels.
// @author lyt
// @date 2026-10-29
type nodePanel struct {
	client *panelClient
	users  []panelUser
	etag   string
}

type identifiedPanelUser struct {
	name  string
	user  panelUser
	panel *nodePanel
}

func createNodePanels(options option.XBoardServiceOptions, tag, nodeType string) (*nodePanel, []*nodePanel, error) {
	configs := options.Panels
	if configs == nil {
		configs = []option.XBoardPanelOptions{{
			PanelTag: tag, PanelType: options.PanelType, APIHost: options.APIHost, APIKey: options.APIKey,
			NodeID: options.NodeID, NodeType: nodeType, Timeout: options.Timeout,
		}}
	} else if len(configs) == 0 {
		return nil, nil, E.New("multi panel node requires at least one panel")
	}
	var primary *nodePanel
	panels := make([]*nodePanel, 0, len(configs))
	indexes := make(map[string]int)
	for _, config := range configs {
		client, err := newPanelClient(config)
		if err != nil {
			return nil, nil, err
		}
		panel := &nodePanel{client: client}
		if primary == nil {
			primary = panel
		}
		if index, exists := indexes[config.PanelTag]; exists {
			panels[index] = panel
		} else {
			indexes[config.PanelTag] = len(panels)
			panels = append(panels, panel)
		}
	}
	if options.Panels == nil {
		panels = nil
	}
	return primary, panels, nil
}

func (n *node) syncPanelUsers(ctx context.Context) error {
	var pullErrors []error
	for _, panel := range n.panels {
		body, status, etag, err := panel.client.request(ctx, http.MethodGet, "user", panel.etag, nil)
		if err != nil {
			err = E.Cause(err, "panel ", panel.client.options.PanelTag)
			n.service.logger.Error("xboard source users retained: ", err)
			pullErrors = append(pullErrors, err)
			continue
		}
		if status == http.StatusNotModified {
			continue
		}
		response, err := panel.client.decodeUsers(body)
		if err != nil {
			err = E.New("invalid users response from panel ", panel.client.options.PanelTag)
			n.service.logger.Error("xboard source users retained: ", err)
			pullErrors = append(pullErrors, err)
			continue
		}
		panel.users, panel.etag = response.Users, etag
		n.usersDirty = true
	}
	if !n.usersDirty {
		return errors.Join(pullErrors...)
	}
	var entries []identifiedPanelUser
	for _, panel := range n.panels {
		for _, user := range panel.users {
			entries = append(entries, identifiedPanelUser{
				name: panel.client.userName(user.ID), user: user, panel: panel,
			})
		}
	}
	if err := n.applyUsers(entries); err != nil {
		pullErrors = append(pullErrors, err)
	} else {
		n.usersDirty = false
		return nil
	}
	return errors.Join(pullErrors...)
}

func (n *node) applyUsers(entries []identifiedPanelUser) error {
	names := make([]string, 0, len(entries))
	credentials := make([]string, 0, len(entries))
	passwords := make([]string, 0, len(entries))
	users := make(map[string]uint64, len(entries))
	limits := make(map[string]usercontrol.Limits, len(entries))
	panels := make(map[string]*nodePanel, len(entries))
	for _, entry := range entries {
		if entry.user.ID == 0 || strings.TrimSpace(entry.user.UUID) == "" {
			continue
		}
		names = append(names, entry.name)
		credentials = append(credentials, entry.user.UUID)
		passwords = append(passwords, entry.user.ProtocolPassword)
		users[entry.name] = entry.user.ID
		limits[entry.name] = n.userLimits(entry.user)
		panels[entry.name] = entry.panel
	}
	if n.control != nil {
		if err := n.control.UpdateUsers(limits); err != nil {
			return E.Cause(err, "update xboard user limits")
		}
	}
	// A newly authenticated stream must already resolve to its panel user when
	// the route policy runs. Removed users are denied by the updated controller.
	n.access.Lock()
	previousUsers, previousPanels := n.users, n.userPanels
	n.users, n.userPanels = users, panels
	n.access.Unlock()
	if err := updateManagedPanelUsers(n.inbound, names, credentials, passwords); err != nil {
		n.access.Lock()
		n.users, n.userPanels = previousUsers, previousPanels
		n.access.Unlock()
		if n.control != nil {
			if rollbackErr := n.control.UpdateUsers(n.limits); rollbackErr != nil {
				return errors.Join(err, E.Cause(rollbackErr, "restore xboard user limits"))
			}
		}
		return E.Cause(err, "update xboard users")
	}
	n.limits = limits
	n.traffic.UpdateUsers(names)
	n.service.logger.Info("xboard users synchronized: ", len(names), " node=", n.nodeID, " type=", n.nodeType)
	return nil
}

package xboard

import (
	"fmt"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// updateManagedPanelUsers preserves the panel UUID separately from protocol passwords.
// @author lyt
// @date 2026-10-29
func updateManagedPanelUsers(inbound adapter.ManagedSSMServer, names, uuids, passwords []string) error {
	if len(names) != len(uuids) || len(names) != len(passwords) {
		return fmt.Errorf("panel users and credentials have different lengths")
	}
	if automatic, ok := inbound.(*autoInbound); ok {
		return automatic.updatePanelUsers(names, uuids, passwords)
	}
	protocol := ""
	for _, password := range passwords {
		if password != "" {
			protocol = inbound.Type()
			break
		}
	}
	credentials, err := panelProtocolCredentials(protocol, uuids, passwords)
	if err != nil {
		return err
	}
	if server, ok := inbound.(interface {
		UpdateUsersWithUUIDs([]string, []string, []string) error
	}); ok {
		return server.UpdateUsersWithUUIDs(names, credentials, uuids)
	}
	return inbound.UpdateUsers(names, credentials)
}

func panelProtocolCredentials(protocol string, uuids, passwords []string) ([]string, error) {
	if len(uuids) != len(passwords) {
		return nil, fmt.Errorf("panel UUIDs and passwords have different lengths")
	}
	credentials := slices.Clone(uuids)
	for index, password := range passwords {
		if password == "" {
			continue
		}
		switch protocol {
		case C.TypeVMess, C.TypeVLESS:
			// UUID protocols use the independently normalized UUID.
		case C.TypeShadowsocks, C.TypeTrojan, C.TypeAnyTLS, C.TypeAnyTLSNative:
			credentials[index] = password
		default:
			return nil, fmt.Errorf("separate panel passwords are unsupported for protocol %s", protocol)
		}
	}
	return credentials, nil
}

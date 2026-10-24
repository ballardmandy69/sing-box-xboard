package xboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/ssmapi"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

// RegisterService registers the XBoard UniProxy client.
func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.XBoardServiceOptions](registry, C.TypeXBoard, NewService)
}

// Service synchronizes XBoard users and traffic for managed inbounds.
// @author lyt
// @date 2026-10-25
type Service struct {
	boxService.Adapter
	ctx    context.Context
	logger log.ContextLogger
	client *http.Client
	nodes  []*node
}

type node struct {
	service       *Service
	inbound       adapter.ManagedSSMServer
	traffic       *ssmapi.TrafficManager
	apiHost       string
	apiKey        string
	nodeID        int
	nodeType      string
	pullInterval  time.Duration
	pushInterval  time.Duration
	disableUpload bool
	access        sync.RWMutex
	users         map[string]int64
	userETag      string
	configETag    string
}

type panelUser struct {
	ID          int64  `json:"id"`
	UUID        string `json:"uuid"`
	SpeedLimit  int64  `json:"speed_limit,omitempty"`
	DeviceLimit int64  `json:"device_limit,omitempty"`
}

type usersResponse struct {
	Users []panelUser `json:"users"`
}

type configResponse struct {
	BaseConfig struct {
		PushInterval int `json:"push_interval"`
		PullInterval int `json:"pull_interval"`
	} `json:"base_config"`
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.XBoardServiceOptions) (adapter.Service, error) {
	if strings.TrimSpace(options.APIHost) == "" {
		return nil, E.New("missing api_host")
	}
	if strings.TrimSpace(options.APIKey) == "" {
		return nil, E.New("missing api_key")
	}
	if options.NodeID <= 0 {
		return nil, E.New("invalid node_id")
	}
	serverEntries := make(map[string]string)
	if options.Servers != nil {
		for _, entry := range options.Servers.Entries() {
			serverEntries[entry.Key] = entry.Value
		}
	}
	if len(serverEntries) == 0 && options.Inbound != "" {
		serverEntries["default"] = options.Inbound
	}
	if len(serverEntries) == 0 {
		return nil, E.New("missing servers or inbound")
	}
	inboundManager := service.FromContext[adapter.InboundManager](ctx)
	if inboundManager == nil {
		return nil, E.New("missing inbound manager")
	}
	pullInterval := time.Duration(options.PullInterval)
	if pullInterval <= 0 {
		pullInterval = time.Minute
	}
	pushInterval := time.Duration(options.PushInterval)
	if pushInterval <= 0 {
		pushInterval = time.Minute
	}
	timeout := time.Duration(options.Timeout)
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	s := &Service{
		Adapter: boxService.NewAdapter(C.TypeXBoard, tag),
		ctx:     ctx,
		logger:  logger,
		client:  &http.Client{Timeout: timeout},
	}
	for key, inboundTag := range serverEntries {
		inbound, loaded := inboundManager.Get(inboundTag)
		if !loaded {
			return nil, E.New("xboard inbound ", inboundTag, " not found")
		}
		managed, ok := inbound.(adapter.ManagedSSMServer)
		if !ok {
			return nil, E.New("inbound/", inbound.Type(), "[", inbound.Tag(), "] is not managed")
		}
		nodeType := options.NodeType
		if nodeType == "" && key != "default" {
			nodeType = key
		}
		s.nodes = append(s.nodes, &node{
			service:       s,
			inbound:       managed,
			traffic:       ssmapi.NewTrafficManager(),
			apiHost:       strings.TrimRight(options.APIHost, "/"),
			apiKey:        options.APIKey,
			nodeID:        options.NodeID,
			nodeType:      nodeType,
			pullInterval:  pullInterval,
			pushInterval:  pushInterval,
			disableUpload: options.DisableUploadTraffic,
			users:         make(map[string]int64),
		})
		node := s.nodes[len(s.nodes)-1]
		managed.SetTracker(node.traffic)
	}
	return s, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	for _, node := range s.nodes {
		go node.loop(scope.Context())
	}
	scope.Add(func() error { return nil })
	return nil
}

func (n *node) loop(ctx context.Context) {
	if err := n.syncUsers(ctx); err != nil {
		n.service.logger.Error("xboard user sync: ", err)
	}
	if err := n.pushTraffic(ctx); err != nil {
		n.service.logger.Error("xboard traffic push: ", err)
	}
	pullTicker := time.NewTicker(n.pullInterval)
	pushTicker := time.NewTicker(n.pushInterval)
	defer pullTicker.Stop()
	defer pushTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-pullTicker.C:
			if err := n.syncUsers(ctx); err != nil {
				n.service.logger.Error("xboard user sync: ", err)
			}
		case <-pushTicker.C:
			if err := n.pushTraffic(ctx); err != nil {
				n.service.logger.Error("xboard traffic push: ", err)
			}
		}
	}
}

func (n *node) syncUsers(ctx context.Context) error {
	config, status, etag, err := n.request(ctx, http.MethodGet, "config", n.configETag, nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		var response configResponse
		if err = json.Unmarshal(config, &response); err != nil {
			return E.Cause(err, "decode xboard config")
		}
		if response.BaseConfig.PullInterval > 0 {
			n.pullInterval = time.Duration(response.BaseConfig.PullInterval) * time.Second
		}
		if response.BaseConfig.PushInterval > 0 {
			n.pushInterval = time.Duration(response.BaseConfig.PushInterval) * time.Second
		}
		n.configETag = etag
	}
	body, status, etag, err := n.request(ctx, http.MethodGet, "user", n.userETag, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotModified {
		return nil
	}
	var response usersResponse
	if err = json.Unmarshal(body, &response); err != nil {
		return E.Cause(err, "decode xboard users")
	}
	names := make([]string, 0, len(response.Users))
	credentials := make([]string, 0, len(response.Users))
	users := make(map[string]int64, len(response.Users))
	for _, user := range response.Users {
		if user.ID <= 0 || strings.TrimSpace(user.UUID) == "" {
			continue
		}
		names = append(names, user.UUID)
		credentials = append(credentials, user.UUID)
		users[user.UUID] = user.ID
	}
	if err = n.inbound.UpdateUsers(names, credentials); err != nil {
		return E.Cause(err, "update xboard users")
	}
	n.traffic.UpdateUsers(names)
	n.access.Lock()
	n.users = users
	n.userETag = etag
	n.access.Unlock()
	n.service.logger.Info("xboard users synchronized: ", len(names), " node=", n.nodeID, " type=", n.nodeType)
	return nil
}

func (n *node) pushTraffic(ctx context.Context) error {
	users := make([]*ssmapi.UserObject, 0)
	n.access.RLock()
	for uuid := range n.users {
		users = append(users, &ssmapi.UserObject{UserName: uuid})
	}
	n.access.RUnlock()
	if len(users) == 0 {
		return nil
	}
	n.traffic.ReadUsers(users, true)
	payload := make(map[string][2]int64, len(users))
	for _, user := range users {
		if user.UplinkBytes == 0 && user.DownlinkBytes == 0 {
			continue
		}
		n.access.RLock()
		id := n.users[user.UserName]
		n.access.RUnlock()
		if id == 0 {
			continue
		}
		up := user.UplinkBytes
		if n.disableUpload {
			up = 0
		}
		payload[strconv.FormatInt(id, 10)] = [2]int64{up, user.DownlinkBytes}
	}
	if len(payload) == 0 {
		return nil
	}
	content, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, status, _, err := n.request(ctx, http.MethodPost, "push", "", content)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected xboard push status: %d", status)
	}
	return nil
}

func (n *node) request(ctx context.Context, method string, endpoint string, etag string, body []byte) ([]byte, int, string, error) {
	requestURL, err := url.Parse(n.apiHost + "/api/v1/server/UniProxy/" + endpoint)
	if err != nil {
		return nil, 0, "", err
	}
	query := requestURL.Query()
	query.Set("token", n.apiKey)
	query.Set("node_id", strconv.Itoa(n.nodeID))
	if n.nodeType != "" {
		query.Set("node_type", n.nodeType)
	}
	requestURL.RawQuery = query.Encode()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), reader)
	if err != nil {
		return nil, 0, "", err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := n.service.client.Do(request)
	if err != nil {
		return nil, 0, "", err
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if readErr != nil {
		return nil, response.StatusCode, "", readErr
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotModified {
		return nil, response.StatusCode, "", errors.New(strings.TrimSpace(string(responseBody)))
	}
	return responseBody, response.StatusCode, response.Header.Get("ETag"), nil
}

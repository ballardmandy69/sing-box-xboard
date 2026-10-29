package xboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/nodepolicy"
	"github.com/sagernet/sing-box/common/usercontrol"
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
	ctx          context.Context
	logger       log.ContextLogger
	policy       *nodepolicy.Registry
	policyAccess sync.Mutex
	policyClosed bool
	nodes        []*node
}

type node struct {
	debugTag        string
	panelTag        string
	staticInbound   bool
	staticUsers     map[string]string
	authUUIDs       map[string]string
	service         *Service
	inbound         adapter.ManagedSSMServer
	traffic         *ssmapi.TrafficManager
	accessLog       *accessLogQueue
	hotUsers        *hotUsers
	control         *usercontrol.Manager
	limits          map[string]usercontrol.Limits
	ipLimit         uint16
	connectionLimit uint32
	maxSpeed        uint64
	nodeID          int
	nodeType        string
	pullInterval    time.Duration
	pushInterval    time.Duration
	syncInterval    time.Duration
	disableUpload   bool
	reportAlive     bool
	trafficFactor   float64
	access          sync.RWMutex
	pushAccess      sync.Mutex
	illegalAccess   sync.Mutex
	illegal         []panelIllegalRecord
	users           map[string]uint64
	userPanels      map[string]*nodePanel
	primary         *nodePanel
	panels          []*nodePanel
	usersDirty      bool
	userETag        string
	configETag      string
	pendingUsers    *pendingUserUpdate
	pendingConfig   *pendingNodeConfig
	auto            *autoInbound
	autoOptions     option.XBoardAutoInboundOptions
}

// pendingNodeConfig retains a decoded response until its local listener changes are committed.
// @author lyt
// @date 2026-10-29
type pendingNodeConfig struct {
	response autoConfigResponse
	etag     string
}

// pendingUserUpdate keeps a single source's decoded users across a failed local application.
// @author lyt
// @date 2026-10-29
type pendingUserUpdate struct {
	users []panelUser
	etag  string
}

type panelUser struct {
	ID               uint64  `json:"id"`
	UUID             string  `json:"uuid"`
	ProtocolPassword string  `json:"-"`
	SpeedLimit       int64   `json:"speed_limit,omitempty"`
	SpeedLimitBytes  *uint64 `json:"-"`
	DeviceLimit      int16   `json:"device_limit,omitempty"`
	ConnectionLimit  int32   `json:"connection_limit,omitempty"`
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
	if options.StaticInbound && options.AutoInbound != nil {
		return nil, E.New("static_inbound and auto_inbound cannot be enabled together")
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
	if len(serverEntries) == 0 && options.StaticInbound && tag != "" {
		serverEntries["default"] = tag
	}
	if len(serverEntries) == 0 {
		return nil, E.New("missing servers or inbound")
	}
	inboundManager := service.FromContext[adapter.InboundManager](ctx)
	if inboundManager == nil && !options.StaticInbound {
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
	var syncInterval time.Duration
	if options.SyncInterval != nil {
		syncInterval = legacySyncInterval(time.Duration(*options.SyncInterval))
	}
	maximum, validMaximum := parseMaximumSpeed(options.MaxSpeedLimit)
	if !validMaximum {
		logger.Warn("invalid node MaxSpeedLimit; falling back to the global setting")
	}
	if maximum == 0 {
		maximum, validMaximum = parseMaximumSpeed(options.DefaultMaxSpeedLimit)
		if !validMaximum {
			logger.Warn("invalid global MaxSpeedLimit; bandwidth cap disabled")
		}
	}
	s := &Service{
		Adapter: boxService.NewAdapter(C.TypeXBoard, tag),
		ctx:     ctx,
		logger:  logger,
	}
	s.policy, _ = service.FromContext[adapter.ManagedNodePolicy](ctx).(*nodepolicy.Registry)
	if options.StaticInbound && s.policy == nil {
		return nil, E.New("static_inbound requires the panel route registry")
	}
	legacyOptions := service.PtrFromContext[option.NYAFWOptions](ctx)
	var hotSeconds int64
	if legacyOptions != nil {
		hotSeconds = legacyOptions.HotUserCacheSec
	}
	hotTTL, err := hotUserTTL(hotSeconds)
	if err != nil {
		return nil, err
	}
	var accessClient *accessLogClient
	var accessTracker *accessLogTracker
	if legacyOptions != nil {
		var err error
		accessClient, err = newAccessLogClient(legacyOptions.SbAPI)
		if err != nil {
			return nil, err
		}
		accessTracker = &accessLogTracker{queues: make(map[string]*accessLogQueue), policy: s.policy}
	}
	for key, inboundTag := range serverEntries {
		if err := checkInboundOwnership(ctx, s, inboundTag); err != nil {
			return nil, err
		}
		nodeType := options.NodeType
		if nodeType == "" && key != "default" {
			nodeType = key
		}
		primary, panels, err := createNodePanels(options, tag, nodeType)
		if err != nil {
			return nil, err
		}
		nodeType = primary.client.protocolType()
		debugTag := primary.client.options.PanelTag
		if options.LegacyPanelTag != nil {
			debugTag = *options.LegacyPanelTag
		}
		node := &node{
			debugTag:        debugTag,
			panelTag:        inboundTag,
			staticInbound:   options.StaticInbound,
			service:         s,
			traffic:         ssmapi.NewTrafficManager(),
			limits:          make(map[string]usercontrol.Limits),
			ipLimit:         options.IPLimit,
			connectionLimit: options.ConnectionLimit,
			maxSpeed:        maximum,
			primary:         primary,
			panels:          panels,
			nodeID:          primary.client.options.NodeID,
			nodeType:        nodeType,
			pullInterval:    pullInterval,
			pushInterval:    pushInterval,
			syncInterval:    syncInterval,
			disableUpload:   options.DisableUploadTraffic,
			reportAlive:     options.ReportAlive,
			users:           make(map[string]uint64),
		}
		if !options.StaticInbound {
			inbound, loaded := inboundManager.Get(inboundTag)
			if _, owned := inbound.(*autoInbound); loaded && owned {
				return nil, E.New("xboard inbound ", inboundTag, " already belongs to another panel node")
			}
			if !loaded {
				if options.AutoInbound == nil {
					return nil, E.New("xboard inbound ", inboundTag, " not found")
				}
				var err error
				inbound, err = node.createInbound(ctx, inboundManager, inboundTag, *options.AutoInbound)
				if err != nil {
					return nil, E.Cause(err, "create xboard inbound ", inboundTag)
				}
			}
			managed, ok := inbound.(adapter.ManagedSSMServer)
			if !ok {
				return nil, E.New("inbound/", inbound.Type(), "[", inbound.Tag(), "] is not managed")
			}
			node.inbound = managed
			if hotManager, ok := managed.(adapter.HotUserManager); ok {
				node.hotUsers = newHotUsers(hotManager, hotTTL)
			}
		}
		trafficFactor := options.TrafficFactor
		if trafficFactor <= 0 {
			trafficFactor = 1
		}
		node.trafficFactor = trafficFactor
		node.control = usercontrol.NewManagerWithRequestLimit(node.traffic, options.RateLimit)
		node.control.SetConnectionCleaner(service.PtrFromContext[usercontrol.ConnectionCleaner](ctx))
		if node.inbound != nil && s.policy == nil {
			node.inbound.SetTracker(node.control)
		}
		if accessTracker != nil {
			node.accessLog = newAccessLogQueue(legacyOptions.AccessLog, accessClient)
			accessTracker.queues[inboundTag] = node.accessLog
		}
		s.nodes = append(s.nodes, node)
	}
	if accessTracker != nil {
		router := service.FromContext[adapter.Router](ctx)
		if router == nil {
			return nil, E.New("missing router for nyafw access records")
		}
		router.AppendTracker(accessTracker)
	}
	return s, nil
}

func checkInboundOwnership(ctx context.Context, current *Service, tag string) error {
	services := []adapter.Service{current}
	if manager := service.FromContext[adapter.ServiceManager](ctx); manager != nil {
		services = append(services, manager.Services()...)
	}
	for _, candidate := range services {
		owner, ok := candidate.(*Service)
		if !ok {
			continue
		}
		for _, node := range owner.nodes {
			if node.policyTag() == tag {
				return E.New("xboard inbound ", tag, " is already managed by another panel node")
			}
		}
	}
	return nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(s.closeNodePolicies)
		for _, node := range s.nodes {
			if err := node.syncNodePolicy(scope.Context()); err != nil {
				return err
			}
		}
	}
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
	if n.syncInterval > 0 {
		n.legacyLoop(ctx)
		return
	}
	if !n.initialSync(ctx) {
		return
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
			previousPull, previousPush := n.pullInterval, n.pushInterval
			if err := n.syncUsers(ctx); err != nil {
				n.service.logger.Error("xboard user sync: ", err)
			}
			if n.pullInterval != previousPull {
				pullTicker.Reset(n.pullInterval)
			}
			if n.pushInterval != previousPush {
				pushTicker.Reset(n.pushInterval)
			}
		case <-pushTicker.C:
			if err := n.pushReports(ctx); err != nil {
				n.service.logger.Error("xboard reports: ", err)
			}
		}
	}
}

// legacyLoop preserves one sleep-after-completion cycle for nyafw-shaped Nodes.
func (n *node) legacyLoop(ctx context.Context) {
	if !n.initialSync(ctx) {
		return
	}
	timer := time.NewTimer(n.syncInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := n.syncCycle(ctx); err != nil {
				n.service.logger.Error("xboard synchronization cycle: ", err)
			}
			timer.Reset(n.syncInterval)
		}
	}
}

func (n *node) initialSync(ctx context.Context) bool {
	if !n.retryInitial(ctx, "users", n.syncUserList) {
		return false
	}
	refreshUsers := false
	synchronized := n.retryInitial(ctx, "node configuration", func(ctx context.Context) error {
		// Some credentials can only be validated after the panel supplies the cipher.
		if refreshUsers {
			if err := n.syncUserList(ctx); err != nil {
				return err
			}
		}
		err := n.syncConfig(ctx)
		refreshUsers = errors.Is(err, errCachedUsersInvalid)
		return err
	})
	if synchronized && n.accessLog != nil {
		interval := n.syncInterval
		if interval == 0 {
			interval = n.pushInterval
		}
		go n.accessLogLoop(ctx, interval)
	}
	return synchronized
}

func (n *node) retryInitial(ctx context.Context, operation string, synchronize func(context.Context) error) bool {
	delay := time.Second
	for ctx.Err() == nil {
		if err := synchronize(ctx); err == nil {
			return true
		} else {
			n.service.logger.Error("xboard initial ", operation, " sync failed; retry in ", delay, ": ", err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
		delay = min(2*delay, 30*time.Second)
	}
	return false
}

func legacySyncInterval(interval time.Duration) time.Duration {
	if interval < 10*time.Second {
		return time.Minute
	}
	return interval
}

func (n *node) syncCycle(ctx context.Context) error {
	// Account for the previous user set before applying removals or listener changes.
	reportErr := n.pushReports(ctx)
	userErr := n.syncUserList(ctx)
	statusErr := n.pushStatus(ctx)
	return errors.Join(reportErr, userErr, statusErr, n.syncConfig(ctx))
}

func (n *node) pushReports(ctx context.Context) error {
	trafficErr := n.pushTraffic(ctx)
	aliveErr := n.pushAlive(ctx)
	return errors.Join(trafficErr, aliveErr, n.pushIllegal(ctx))
}

func (n *node) syncUsers(ctx context.Context) error {
	// A rejected listener configuration must not postpone user revocation.
	statusErr := n.pushStatus(ctx)
	configErr := n.syncConfig(ctx)
	return errors.Join(statusErr, configErr, n.syncUserList(ctx))
}

func (n *node) syncConfig(ctx context.Context) error {
	config, status, etag, err := n.request(ctx, http.MethodGet, "config", n.configETag, nil)
	if err != nil {
		if successfulStatus(status) {
			// A new, undecodable provider payload must not replay an older pending response.
			n.pendingConfig = nil
		}
		return err
	}
	if successfulStatus(status) {
		n.pendingConfig = nil
		var response autoConfigResponse
		if err = json.Unmarshal(config, &response); err != nil {
			return E.New("invalid xboard node configuration response")
		}
		response.providerNormalized = n.primary != nil && n.primary.client.provider != nil
		if n.primary != nil && n.primary.client != nil {
			response.rawNodeType = n.primary.client.options.NodeType
		}
		n.pendingConfig = &pendingNodeConfig{response: response, etag: etag}
	} else if status == http.StatusNotModified {
		if n.pendingConfig == nil && n.auto != nil && !n.auto.hasCurrent() {
			return E.New("initial xboard node configuration cannot be unchanged before a listener exists")
		}
	} else {
		return nil
	}
	n.refreshNodeRules(ctx)
	if err = n.syncNodePolicy(ctx); err != nil {
		return err
	}
	if n.pendingConfig == nil {
		return nil
	}
	pending := n.pendingConfig
	if n.auto != nil {
		candidate, err := pending.response.buildInboundConfig(n.nodeType, n.autoOptions)
		if err != nil {
			return E.Cause(err, "xboard configuration rejected; previous inbound retained")
		}
		if err = n.auto.replace(candidate); err != nil {
			return E.Cause(err, "xboard configuration update failed")
		}
	}
	n.applyConfigIntervals(pending.response.configResponse)
	n.configETag = pending.etag
	n.pendingConfig = nil
	return nil
}

func (n *node) syncUserList(ctx context.Context) error {
	if n.panels != nil {
		return n.syncPanelUsers(ctx)
	}
	body, status, etag, err := n.request(ctx, http.MethodGet, "user", n.userETag, nil)
	if err != nil {
		if successfulStatus(status) {
			n.pendingUsers = nil
		}
		return err
	}
	if status != http.StatusNotModified {
		n.pendingUsers = nil
		response, err := n.primary.client.decodeUsers(body)
		if err != nil {
			return E.Cause(err, "decode xboard users")
		}
		n.pendingUsers = &pendingUserUpdate{users: response.Users, etag: etag}
	}
	if n.pendingUsers == nil {
		return nil
	}
	pending := n.pendingUsers
	entries := make([]identifiedPanelUser, 0, len(pending.users))
	for _, user := range pending.users {
		entries = append(entries, identifiedPanelUser{name: n.userName(user.ID), user: user})
	}
	if err = n.applyUsers(entries); err == nil {
		n.userETag = pending.etag
		n.pendingUsers = nil
	}
	return err
}

// userName separates accounting identity from the user's replaceable protocol credential.
func (n *node) userName(id uint64) string {
	return n.primary.client.userName(id)
}

// userLimits preserves the original UniProxy integer conversion and nonzero user overrides.
// @author lyt
// @date 2026-10-29
func (n *node) userLimits(user panelUser) usercontrol.Limits {
	// The binary multiplies in 64 bits and then performs an unsigned shift, including signed input values.
	speed := uint64(user.SpeedLimit*1_000_000) >> 3
	if user.SpeedLimitBytes != nil {
		speed = *user.SpeedLimitBytes
	}
	if speed == 0 || n.maxSpeed != 0 && speed > n.maxSpeed {
		speed = n.maxSpeed
	}
	ipLimit := uint16(user.DeviceLimit)
	if ipLimit == 0 {
		ipLimit = n.ipLimit
	}
	connectionLimit := uint32(user.ConnectionLimit)
	if connectionLimit == 0 {
		connectionLimit = n.connectionLimit
	}
	return usercontrol.Limits{
		UploadBytesPerSecond: speed, DownloadBytesPerSecond: speed,
		IPLimit: uint32(ipLimit), ConnectionLimit: connectionLimit,
	}
}

func (n *node) applyConfigIntervals(response configResponse) {
	if n.syncInterval > 0 {
		return
	}
	if response.BaseConfig.PullInterval > 0 {
		n.pullInterval = time.Duration(response.BaseConfig.PullInterval) * time.Second
	}
	if response.BaseConfig.PushInterval > 0 {
		n.pushInterval = time.Duration(response.BaseConfig.PushInterval) * time.Second
	}
}

func (n *node) pushTraffic(ctx context.Context) error {
	if n.disableUpload {
		return nil
	}
	n.pushAccess.Lock()
	defer n.pushAccess.Unlock()
	users := make([]string, 0)
	userIDs := make(map[string]uint64)
	userPanels := make(map[string]*nodePanel)
	n.access.RLock()
	for name, id := range n.users {
		users = append(users, name)
		userIDs[name] = id
		userPanels[name] = n.userPanels[name]
	}
	n.access.RUnlock()
	if len(users) == 0 {
		n.hotUsers.refresh(nil)
		return nil
	}
	snapshots := n.traffic.SnapshotTraffic(users)
	// Original hot authentication maintenance precedes traffic-report acknowledgement.
	n.hotUsers.refresh(snapshots)
	type trafficBatch struct {
		payload   map[string][2]int64
		snapshots []*ssmapi.UserTrafficSnapshot
	}
	batches := make(map[*nodePanel]*trafficBatch)
	var reportErrors []error
	for _, user := range snapshots {
		if user.UplinkBytes == 0 && user.DownlinkBytes == 0 {
			continue
		}
		id := userIDs[user.UserName]
		if id == 0 {
			continue
		}
		panel := userPanels[user.UserName]
		if n.panels != nil && panel == nil {
			reportErrors = append(reportErrors, E.New("traffic user has no panel source"))
			continue
		}
		batch := batches[panel]
		if batch == nil {
			batch = &trafficBatch{payload: make(map[string][2]int64)}
			batches[panel] = batch
		}
		batch.payload[strconv.FormatUint(id, 10)] = [2]int64{
			int64(math.Ceil(float64(user.UplinkBytes) * n.trafficFactor)),
			int64(math.Ceil(float64(user.DownlinkBytes) * n.trafficFactor)),
		}
		batch.snapshots = append(batch.snapshots, user)
	}
	for panel, batch := range batches {
		content, err := json.Marshal(batch.payload)
		if err != nil {
			reportErrors = append(reportErrors, err)
			continue
		}
		request := n.request
		if panel != nil {
			request = panel.client.request
		}
		_, status, _, err := request(ctx, http.MethodPost, "push", "", content)
		if err == nil && !successfulStatus(status) {
			err = fmt.Errorf("unexpected xboard push status: %d", status)
		}
		if err != nil {
			reportErrors = append(reportErrors, err)
			continue
		}
		for _, snapshot := range batch.snapshots {
			snapshot.Acknowledge()
		}
	}
	return errors.Join(reportErrors...)
}

func (n *node) pushAlive(ctx context.Context) error {
	if !n.reportAlive || n.panels != nil {
		return nil
	}
	payload := make(map[string][]string)
	if n.control != nil {
		online := n.control.OnlineIPs()
		n.access.RLock()
		for name, addresses := range online {
			id, exists := n.users[name]
			if !exists {
				continue
			}
			ips := make([]string, len(addresses))
			for index, address := range addresses {
				ips[index] = address.String()
			}
			payload[strconv.FormatUint(id, 10)] = ips
		}
		n.access.RUnlock()
	}
	content, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, status, _, err := n.request(ctx, http.MethodPost, "alive", "", content)
	if err != nil {
		return err
	}
	if !successfulStatus(status) {
		return fmt.Errorf("unexpected xboard alive status: %d", status)
	}
	return nil
}

func (n *node) request(ctx context.Context, method string, endpoint string, etag string, body []byte) ([]byte, int, string, error) {
	return n.primary.client.request(ctx, method, endpoint, etag, body)
}

func successfulStatus(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

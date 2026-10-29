package box

import (
	"context"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
)

func startDebugHTTPServer(ctx context.Context, options option.DebugOptions) (*http.Server, error) {
	if options.Listen == "" {
		return nil, nil
	}
	server := &http.Server{Addr: options.Listen, Handler: newDebugHTTPHandler(ctx)}
	listener, err := net.Listen("tcp", options.Listen)
	if err != nil {
		return nil, E.Cause(err, "listen debug HTTP server")
	}
	go func() {
		err := server.Serve(listener)
		if err != nil && !E.IsClosed(err) {
			log.Error(E.Cause(err, "serve debug HTTP server"))
		}
	}()
	return server, nil
}

func newDebugHTTPHandler(ctx context.Context) http.Handler {
	r := chi.NewMux()
	r.Route("/debug", func(r chi.Router) {
		r.Get("/gc", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
			go debug.FreeOSMemory()
		})
		r.Get("/memory", func(writer http.ResponseWriter, request *http.Request) {
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)

			var memObject badjson.JSONObject
			memObject.Put("heap", byteformats.FormatIBytes(memStats.HeapInuse))
			memObject.Put("stack", byteformats.FormatIBytes(memStats.StackInuse))
			memObject.Put("idle", byteformats.FormatIBytes(memStats.HeapIdle-memStats.HeapReleased))
			memObject.Put("goroutines", runtime.NumGoroutine())
			memObject.Put("rss", currentRSS())
			memObject.Put("maxRss", rusageMaxRSS())

			encoder := json.NewEncoder(writer)
			encoder.SetIndent("", "  ")
			encoder.Encode(&memObject)
		})
		r.Get("/connections", func(writer http.ResponseWriter, request *http.Request) {
			top, err := strconv.Atoi(request.URL.Query().Get("top"))
			if err != nil || top < 0 {
				top = 100
			}
			var registrations []usercontrol.Registration
			if cleaner := service.PtrFromContext[usercontrol.ConnectionCleaner](ctx); cleaner != nil {
				registrations = cleaner.SnapshotRegistrations()
			}
			writer.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(writer)
			encoder.SetIndent("", "  ")
			encoder.Encode(groupDebugConnections(registrations, top))
		})
		r.HandleFunc("/pprof", pprof.Index)
		r.HandleFunc("/pprof/*", pprof.Index)
		r.HandleFunc("/pprof/cmdline", pprof.Cmdline)
		r.HandleFunc("/pprof/profile", pprof.Profile)
		r.HandleFunc("/pprof/symbol", pprof.Symbol)
		r.HandleFunc("/pprof/trace", pprof.Trace)
	})
	r.Get("/sb/debug/users", func(writer http.ResponseWriter, request *http.Request) {
		manager := service.FromContext[adapter.ServiceManager](ctx)
		if manager == nil {
			return
		}
		hasProvider := false
		for _, item := range manager.Services() {
			provider, ok := item.(adapter.DebugHotUserProvider)
			if !ok {
				continue
			}
			hasProvider = true
			users, found := provider.DebugHotUsers(request.URL.Query().Get("tag"))
			if found {
				content, err := json.Marshal(users)
				if err == nil {
					writer.Write(content)
				}
				return
			}
		}
		if hasProvider {
			writer.Write([]byte("wrong tag"))
		}
	})
	return r
}

func currentRSS() float64 {
	content, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	return parseCurrentRSS(content, os.Getpagesize())
}

func parseCurrentRSS(content []byte, pageSize int) float64 {
	fields := strings.Fields(string(content))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return float64(pages*uint64(pageSize)) / (1 << 20)
}

// debugConnectionKey is the original registration metadata grouping key.
// @author lyt
// @date 2026-10-29
type debugConnectionKey struct {
	Type      string `json:"type"`
	SourceIP  string `json:"sourceIP,omitempty"`
	UserLabel string `json:"userLabel,omitempty"`
}

// debugConnectionGroup combines all registrations with the same metadata.
// @author lyt
// @date 2026-10-29
type debugConnectionGroup struct {
	debugConnectionKey
	Count   int   `json:"count"`
	Traffic int64 `json:"traffic"`
}

// debugConnections preserves the original total before applying the group limit.
// @author lyt
// @date 2026-10-29
type debugConnections struct {
	Registrations int                    `json:"registrations"`
	Groups        []debugConnectionGroup `json:"groups"`
}

func groupDebugConnections(registrations []usercontrol.Registration, top int) debugConnections {
	groups := make(map[debugConnectionKey]debugConnectionGroup)
	for _, entry := range registrations {
		key := debugConnectionKey{entry.Type, entry.SourceIP, entry.UserLabel}
		group := groups[key]
		group.debugConnectionKey = key
		group.Count++
		group.Traffic += entry.Traffic
		groups[key] = group
	}
	result := debugConnections{Registrations: len(registrations), Groups: make([]debugConnectionGroup, 0, len(groups))}
	for _, group := range groups {
		result.Groups = append(result.Groups, group)
	}
	slices.SortFunc(result.Groups, func(a, b debugConnectionGroup) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		if order := strings.Compare(a.Type, b.Type); order != 0 {
			return order
		}
		if order := strings.Compare(a.UserLabel, b.UserLabel); order != 0 {
			return order
		}
		return strings.Compare(a.SourceIP, b.SourceIP)
	})
	if top >= 0 && top < len(result.Groups) {
		result.Groups = result.Groups[:top]
	}
	return result
}

package hub

// Moving a server's own model key to the hub. A server's [inference]
// endpoint and key were its own (kodeblue inference, or an older
// enrollment's copy of the fleet default). On upgrade the installer runs
// kodeblue move-keys as root: the server hands both to the hub, the hub takes
// them over as a connection for that server and picks the same models on it,
// and the server empties its key file. A key the server holds without an
// endpoint the hub can use it with (a leftover key file) is kept aside on
// the hub, so the server can delete it all the same. From then on root on
// the server finds no model key there. A server moves keys only to a hub at
// least as new as itself: every reply carries the hub's version.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func (s *Server) moveKeysRoutes() {
	s.mux.HandleFunc("POST "+hubproto.PathMoveKeys, s.agent(s.handleMoveKeys))
	s.mux.HandleFunc("GET /api/settings/kept-keys", s.op(s.handleKeptKeys))
	s.mux.HandleFunc("DELETE /api/settings/kept-keys/{id}", s.op(s.handleKeptKeyDelete))
	s.mux.HandleFunc("POST /api/settings/kept-keys/{id}/connection", s.op(s.handleKeptKeyConnection))
}

func (s *Server) keptKeyViews() []KeptKey {
	out := s.st.KeptKeys()
	if out == nil {
		out = []KeptKey{}
	}
	return out
}

func (s *Server) handleKeptKeys(w http.ResponseWriter, r *http.Request, c *opCtx) {
	writeJSON(w, http.StatusOK, map[string]any{"kept_keys": s.keptKeyViews()})
}

func keptKeyID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusNotFound, "no such key")
		return 0, false
	}
	return id, true
}

func (s *Server) handleKeptKeyDelete(w http.ResponseWriter, r *http.Request, c *opCtx) {
	id, ok := keptKeyID(w, r)
	if !ok {
		return
	}
	k, ok := s.st.keptKey(id)
	if !ok || !s.st.dropKeptKey(id) {
		writeErr(w, http.StatusNotFound, "no such key")
		return
	}
	s.st.Audit(c.user.Name, "settings.kept_key_delete", k.ServerID, "key "+k.Sum, c.ip)
	writeJSON(w, http.StatusOK, map[string]any{"kept_keys": s.keptKeyViews()})
}

// handleKeptKeyConnection makes a connection with a kept key. Operators
// never see a stored key, so it goes only to the endpoint the server used it
// with (scheme, host and port; the path may differ), as with a connection
// moved to another host: a key nothing says where it belongs can only be
// deleted.
func (s *Server) handleKeptKeyConnection(w http.ResponseWriter, r *http.Request, c *opCtx) {
	id, ok := keptKeyID(w, r)
	if !ok {
		return
	}
	var req connectionReq
	if err := readJSON(w, r, 16<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	k, ok := s.st.keptKey(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "no such key")
		return
	}
	req.APIKey, req.Direct = k.Key, nil
	if err := req.check(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if k.SeenWith == "" {
		writeErr(w, http.StatusConflict, "the server named no endpoint for this key, so the hub never sends it anywhere: it can only be deleted")
		return
	}
	if !sameOrigin(req.BaseURL, k.SeenWith) {
		writeErr(w, http.StatusConflict, "this key goes only to "+k.SeenWith+", the endpoint the server used it with")
		return
	}
	list := s.st.Connections()
	if len(list) >= 32 {
		writeErr(w, http.StatusBadRequest, "at most 32 connections")
		return
	}
	conn := hubproto.Connection{ID: newConnectionID(req.Name, req.Kind, list), Kind: req.Kind, Name: req.Name, BaseURL: req.BaseURL, APIKey: k.Key}
	if err := s.st.setConnections(append(list, conn)); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	s.st.dropKeptKey(id)
	s.models.forget(conn.ID)
	s.st.Audit(c.user.Name, "settings.connection_add", conn.ID, fmt.Sprintf("kind=%s url=%s from kept key %s", conn.Kind, conn.BaseURL, k.Sum), c.ip)
	writeJSON(w, http.StatusOK, map[string]any{"id": conn.ID, "connections": s.connectionViews(), "kept_keys": s.keptKeyViews()})
}

// onServer reports whether an endpoint is on the server itself (loopback or
// link-local), where only that server reaches it: its key stays there.
func onServer(raw string) bool {
	a, ok := endpointAddr(raw)
	return ok && (a.IsLoopback() || a.IsLinkLocalUnicast())
}

func (s *Server) handleMoveKeys(w http.ResponseWriter, r *http.Request, id string) {
	var req hubproto.MoveKeysRequest
	if err := readJSON(w, r, 64<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	srv := s.st.GetServer(id)
	if srv == nil {
		writeErr(w, http.StatusNotFound, "no such server")
		return
	}
	// Whatever else happens, the server calls hub connections through the
	// hub from now on, and never gets their keys again.
	s.st.markModelProxy(id)
	req.Key = strings.TrimSpace(req.Key)
	if req.Key == "" {
		writeJSON(w, http.StatusOK, hubproto.MoveKeysResponse{HubVersion: hubproto.Version})
		return
	}
	// Each attempt counts: a server could otherwise have the hub probe
	// addresses on its network with test calls.
	if s.moveLimit.Reserve(id) == nil {
		writeErr(w, http.StatusTooManyRequests, "too many attempts to move this server's model key; wait an hour")
		return
	}
	// One move at a time, so the one-connection-per-server limit holds.
	s.moveMu.Lock()
	conn, err := s.takeOverKey(r, srv, req)
	s.moveMu.Unlock()
	if err != nil {
		s.st.Audit("server:"+srv.Name, "server.keys_move_refused", id, err.Error(), s.clientIP(r))
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	conn.HubVersion = hubproto.Version
	writeJSON(w, http.StatusOK, conn)
}

// takeOverKey finds or creates the connection for the server's endpoint and
// key, and picks the server's models on it for the roles that used its own
// endpoint.
func (s *Server) takeOverKey(r *http.Request, srv *Host, req hubproto.MoveKeysRequest) (hubproto.MoveKeysResponse, error) {
	var out hubproto.MoveKeysResponse
	if strings.TrimSpace(req.BaseURL) == "" {
		// A key the server does not call an endpoint with: when a
		// connection has it, the server just drops it; otherwise the hub
		// keeps it aside for an operator, and the server drops it too.
		if len(req.Key) > 1024 || strings.ContainsAny(req.Key, " \t\r\n") {
			return out, fmt.Errorf("the key must be a single line")
		}
		sum := hubproto.KeySum(req.Key)
		for _, c := range s.st.Connections() {
			if c.APIKey != "" && hubproto.KeySum(c.APIKey) == sum {
				out.Connection = c.ID
				s.st.Audit("server:"+srv.Name, "server.keys_moved", srv.ID, fmt.Sprintf("connection %s (existing, key only)", c.ID), s.clientIP(r))
				return out, nil
			}
		}
		seen := normalizeBaseURL(req.SeenWith)
		if ValidateEndpointURL(seen) != nil || len(seen) > 512 {
			seen = ""
		}
		if err := s.st.keepKey(srv.ID, srv.Name, req.Key, seen); err != nil {
			return out, err
		}
		out.Kept = true
		s.st.Audit("server:"+srv.Name, "server.keys_kept", srv.ID, fmt.Sprintf("key %s kept aside (seen with %q, as the server says)", sum, seen), s.clientIP(r))
		return out, nil
	}
	cr := connectionReq{Kind: hubproto.ConnOpenAI, Name: trim(srv.Name, 40) + " (moved from the server)", BaseURL: req.BaseURL, APIKey: req.Key}
	if err := cr.check(); err != nil {
		return out, err
	}
	if onServer(cr.BaseURL) {
		return out, fmt.Errorf("%s is on the server itself, where the hub cannot reach it: its key stays there", cr.BaseURL)
	}
	routed := false // a role names a vendor: a multi-vendor gateway
	for role, m := range req.Models {
		if !slices.Contains(hubproto.ModelRoles, role) || m.Model == "" || len(m.Model) > 200 || strings.ContainsAny(m.Model, "\r\n") || !hubproto.ValidProvider(m.Provider) {
			return out, fmt.Errorf("bad model for %q", role)
		}
		if p := m.Provider; p != "" && p != hubproto.ConnOpenAI && p != "openai" {
			routed = true
		}
	}
	switch {
	case strings.HasPrefix(cr.BaseURL, OpenRouterURL):
		cr.Kind = hubproto.ConnOpenRouter
	case routed:
		cr.Kind = hubproto.ConnInferenceManager
	}

	list := s.st.Connections()
	sum := hubproto.KeySum(cr.APIKey)
	i := slices.IndexFunc(list, func(c hubproto.Connection) bool {
		return c.BaseURL == cr.BaseURL && c.APIKey != "" && hubproto.KeySum(c.APIKey) == sum
	})
	if i >= 0 {
		out.Connection = list[i].ID
		cr.Kind = list[i].Kind
	} else {
		// One new connection per server: a server cannot fill the hub with
		// endpoints of its choosing.
		if prev := s.st.movedConnection(srv.ID); prev != "" && slices.ContainsFunc(list, func(c hubproto.Connection) bool { return c.ID == prev }) {
			return out, fmt.Errorf("this server already moved another endpoint to the hub (connection %s): pick its models in the hub's Settings", prev)
		}
		if len(list) >= 32 {
			return out, fmt.Errorf("the hub has 32 model connections, the most it keeps")
		}
		conn := hubproto.Connection{ID: newConnectionID(srv.Name, cr.Kind, list), Kind: cr.Kind, Name: cr.Name, BaseURL: cr.BaseURL, APIKey: cr.APIKey}
		// Only an endpoint the hub can reach: otherwise the server would be
		// left with no models.
		// How the endpoint failed stays in the hub's log: the server learns
		// nothing about addresses on the hub's network from the reply.
		if _, err := fetchModels(r.Context(), s.models.client, conn); err != nil {
			s.log.Warn("move-keys: the hub cannot use the server's endpoint", "server", srv.ID, "url", conn.BaseURL, "error", err)
			return out, fmt.Errorf("the hub cannot use %s with this key (its log says why): the key stays on the server", conn.BaseURL)
		}
		if err := s.st.setConnections(append(list, conn)); err != nil {
			return out, fmt.Errorf("store failed")
		}
		s.st.setMovedConnection(srv.ID, conn.ID)
		list = append(list, conn)
		out.Connection, out.Created = conn.ID, true
	}

	own := s.st.ServerAgentSettings(srv.ID)
	if own.Models == nil {
		own.Models = map[string]hubproto.ModelRef{}
	}
	for role, m := range req.Models {
		ref := hubproto.ModelRef{Connection: out.Connection, Model: m.Model}
		if cr.Kind == hubproto.ConnInferenceManager {
			ref.Provider = m.Provider
		}
		own.Models[role] = ref
		out.Roles = append(out.Roles, role)
	}
	sort.Strings(out.Roles)
	if err := own.Validate(list); err != nil {
		return out, err
	}
	if err := s.st.SetServerAgentSettings(srv.ID, own); err != nil {
		return out, fmt.Errorf("store failed")
	}
	how := "existing"
	if out.Created {
		how = "new"
	}
	b, _ := json.Marshal(out.Roles)
	s.st.Audit("server:"+srv.Name, "server.keys_moved", srv.ID, fmt.Sprintf("connection %s (%s) url=%s roles=%s", out.Connection, how, cr.BaseURL, b), s.clientIP(r))
	s.log.Info("server moved its model key to the hub", "server", srv.ID, "connection", out.Connection, "new", out.Created)
	return out, nil
}

package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// Shared blocks: when one server blocks an address, the hub tells the rest
// of the fleet, and each blocks it too under its own policy (automatically
// in contain mode, otherwise as a request an operator approves; never what
// the server protects). The hub reads them from the containment actions the
// servers already sync: a block_ip carried out, still in effect, made in the
// last SharedBlockDays days. Only public addresses are shared (a private one
// may be a neighbour on another server's network), never a revoked server's
// blocks, and never a block that was itself shared (no echo).

// settingShareBlocks is "off" when operators turned sharing off; on by default.
const settingShareBlocks = "share_blocks"

// blocksTTL is how long the fleet's blocks are read once and reused: every
// server syncs every few seconds.
const blocksTTL = 30 * time.Second

// fleetBlock is a shared block and the server it came from.
type fleetBlock struct {
	hubproto.SharedBlock
	ServerID string `json:"server_id"`
}

type blockCache struct {
	mu  sync.Mutex
	at  time.Time
	all []fleetBlock
}

func (s *Store) ShareBlocks() bool { return s.Setting(settingShareBlocks) != "off" }

// FleetBlocks lists the blocks every server would share: one per server and
// address (its first), newest first.
func (s *Store) FleetBlocks(now time.Time) []fleetBlock {
	cut := now.Add(-hubproto.SharedBlockDays * 24 * time.Hour)
	var out []fleetBlock
	for _, srv := range s.servers(`WHERE revoked=0 AND key_hash<>''`) {
		rows, err := s.db.Query(`SELECT rid, json_extract(data,'$.params.ip'), json_extract(data,'$.justification'), json_extract(data,'$.done_at'), json_extract(data,'$.requested_by')
FROM records WHERE server_id=? AND kind='action' AND json_extract(data,'$.action')='block_ip' AND json_extract(data,'$.status')='done'`, srv.ID)
		if err != nil {
			continue
		}
		first := map[string]int{} // address -> index in out
		for rows.Next() {
			var rid string
			var ip, why, doneAt, by *string
			if rows.Scan(&rid, &ip, &why, &doneAt, &by) != nil || ip == nil || doneAt == nil {
				continue
			}
			if by != nil && strings.HasPrefix(*by, "fleet") {
				continue
			}
			addr, err := netip.ParseAddr(*ip)
			if addr = addr.Unmap(); err != nil || !addr.IsGlobalUnicast() || addr.IsPrivate() {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, *doneAt)
			if err != nil || at.Before(cut) {
				continue
			}
			b := fleetBlock{ServerID: srv.ID, SharedBlock: hubproto.SharedBlock{ID: sharedBlockID(srv.ID, rid), IP: addr.String(), Server: srv.Name, At: at.UTC()}}
			if why != nil {
				b.Why = trimRunes(strings.Join(strings.Fields(*why), " "), 300)
			}
			if i, ok := first[b.IP]; ok {
				if at.Before(out[i].At) {
					out[i] = b
				}
				continue
			}
			first[b.IP] = len(out)
			out = append(out, b)
		}
		rows.Close()
	}
	slices.SortFunc(out, func(a, b fleetBlock) int {
		if c := b.At.Compare(a.At); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// sharedBlockID names a server's action across the fleet without telling
// other servers its ids.
func sharedBlockID(server, rid string) string {
	h := sha256.Sum256([]byte(server + "/" + rid))
	return "sb_" + hex.EncodeToString(h[:5])
}

// fleetBlocks is FleetBlocks, read at most once per blocksTTL; empty while
// operators turned sharing off.
func (s *Server) fleetBlocks() []fleetBlock {
	if !s.st.ShareBlocks() {
		return nil
	}
	s.blocks.mu.Lock()
	defer s.blocks.mu.Unlock()
	if now := time.Now(); now.Sub(s.blocks.at) >= blocksTTL {
		s.blocks.all, s.blocks.at = s.st.FleetBlocks(now), now
	}
	return s.blocks.all
}

func (s *Server) forgetFleetBlocks() {
	s.blocks.mu.Lock()
	s.blocks.at = time.Time{}
	s.blocks.mu.Unlock()
}

// SharedBlocksFor is what server id is sent: the other servers' blocks, one
// per address (its first), newest first.
func (s *Server) SharedBlocksFor(id string) *hubproto.SharedBlocks {
	out := &hubproto.SharedBlocks{Blocks: []hubproto.SharedBlock{}}
	at := map[string]int{}
	for _, b := range s.fleetBlocks() {
		if b.ServerID == id {
			continue
		}
		if i, ok := at[b.IP]; ok {
			if b.At.Before(out.Blocks[i].At) {
				out.Blocks[i] = b.SharedBlock
			}
			continue
		}
		if len(out.Blocks) == hubproto.MaxSharedBlocks {
			continue
		}
		at[b.IP] = len(out.Blocks)
		out.Blocks = append(out.Blocks, b.SharedBlock)
	}
	data, _ := json.Marshal(out.Blocks)
	sum := sha256.Sum256(data)
	out.Version = hex.EncodeToString(sum[:8])
	return out
}

// ---- operator API ----

func (s *Server) sharedBlockRoutes() {
	s.mux.HandleFunc("GET /api/settings/shared-blocks", s.op(s.handleSharedBlocksGet))
	s.mux.HandleFunc("PUT /api/settings/shared-blocks", s.op(s.handleSharedBlocksPut))
}

type sharedBlocksView struct {
	Enabled bool         `json:"enabled"`
	Days    int          `json:"days"`
	Blocks  []fleetBlock `json:"blocks"`
}

func (s *Server) sharedBlocksView() sharedBlocksView {
	v := sharedBlocksView{Enabled: s.st.ShareBlocks(), Days: hubproto.SharedBlockDays, Blocks: s.st.FleetBlocks(time.Now())}
	if v.Blocks == nil {
		v.Blocks = []fleetBlock{}
	}
	return v
}

func (s *Server) handleSharedBlocksGet(w http.ResponseWriter, r *http.Request, c *opCtx) {
	writeJSON(w, http.StatusOK, s.sharedBlocksView())
}

func (s *Server) handleSharedBlocksPut(w http.ResponseWriter, r *http.Request, c *opCtx) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil || req.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "enabled must be true or false")
		return
	}
	v, action := "", "shared_blocks.on"
	if !*req.Enabled {
		v, action = "off", "shared_blocks.off"
	}
	if err := s.st.SetSetting(settingShareBlocks, v); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.forgetFleetBlocks()
	s.st.Audit(c.user.Name, action, "", "", c.ip)
	writeJSON(w, http.StatusOK, s.sharedBlocksView())
}

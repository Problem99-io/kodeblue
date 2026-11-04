package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
)

func (s *Server) fileChangesGet(_ context.Context, args json.RawMessage) (string, error) {
	var a struct {
		FindingID int64 `json:"finding_id"`
		AfterID   int64 `json:"after_id"`
		ThroughID int64 `json:"through_id"`
		Limit     int   `json:"limit"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	f := s.st.GetFinding(a.FindingID)
	if f == nil || f.Collector != "monitor" || f.Evidence["kind"] != "file" {
		return "", errors.New("finding is not a file-monitor finding")
	}
	if a.Limit == 0 {
		a.Limit = 20
	}
	page, err := s.st.FileChanges(f.ID, a.AfterID, a.ThroughID, a.Limit)
	if err != nil {
		return "", err
	}
	return jsonOut(map[string]any{"finding_id": f.ID, "changes": page.Changes, "through_id": page.ThroughID, "next_after_id": page.NextAfterID, "more": page.More, "evidence_available": f.Evidence["file_changes_available"] == "true"}) + untrusted, nil
}

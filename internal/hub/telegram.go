package hub

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/notify"
)

const (
	settingTelegramToken  = "telegram_bot_token"
	settingTelegramChat   = "telegram_chat_id"
	settingTelegramMinSev = "telegram_min_severity"
)

type TelegramSettings struct {
	Configured  bool   `json:"configured"`
	ChatID      string `json:"chat_id"`
	MinSeverity string `json:"min_severity"`
}

func (s *Store) TelegramSettings() TelegramSettings {
	token, chat, minimum := s.Setting(settingTelegramToken), s.Setting(settingTelegramChat), s.Setting(settingTelegramMinSev)
	if minimum == "" {
		minimum = "info"
	}
	return TelegramSettings{Configured: token != "" && chat != "", ChatID: chat, MinSeverity: minimum}
}

func (s *Server) telegram() *notify.Telegram {
	tg := notify.TelegramFromConfig(s.st.Setting(settingTelegramToken), "", s.st.Setting(settingTelegramChat), "")
	if tg != nil {
		tg.HTTP = s.models.client
	}
	return tg
}

func (s *Server) telegramRoutes() {
	s.mux.HandleFunc("GET /api/settings/telegram", s.op(s.handleTelegramGet))
	s.mux.HandleFunc("PUT /api/settings/telegram", s.op(s.handleTelegramPut))
	s.mux.HandleFunc("POST /api/settings/telegram/test", s.op(s.handleTelegramTest))
}

func (s *Server) handleTelegramGet(w http.ResponseWriter, r *http.Request, c *opCtx) {
	writeJSON(w, http.StatusOK, s.st.TelegramSettings())
}

func (s *Server) handleTelegramPut(w http.ResponseWriter, r *http.Request, c *opCtx) {
	var req struct {
		Token       *string `json:"bot_token"`
		Chat        *string `json:"chat_id"`
		MinSeverity *string `json:"min_severity"`
	}
	if err := readJSON(w, r, 8<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	values := map[string]string{}
	if req.Token != nil {
		token := strings.TrimSpace(*req.Token)
		if token != "" {
			if err := notify.ValidateTelegramToken(token); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		values[settingTelegramToken] = token
	}
	if req.Chat != nil {
		chat := strings.TrimSpace(*req.Chat)
		if chat != "" {
			if err := notify.ValidateTelegramChat(chat); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		values[settingTelegramChat] = chat
	}
	if req.MinSeverity != nil {
		if _, ok := sevRank[*req.MinSeverity]; !ok {
			writeErr(w, http.StatusBadRequest, "min_severity must be info, low, medium, high or critical")
			return
		}
		values[settingTelegramMinSev] = *req.MinSeverity
	}
	tx, err := s.st.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not save Telegram settings")
		return
	}
	defer tx.Rollback()
	for k, v := range values {
		if _, err := tx.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not save Telegram settings")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not save Telegram settings")
		return
	}
	action := "unchanged"
	if req.Token != nil {
		action = "set"
		if strings.TrimSpace(*req.Token) == "" {
			action = "cleared"
		}
	}
	s.resetNotificationProvider("telegram")
	if settings := s.st.TelegramSettings(); !settings.Configured && (s.st.Setting(settingTelegramToken) != "" || settings.ChatID != "") {
		s.log.Warn("Telegram configuration is incomplete; delivery disabled")
	}
	s.st.Audit(c.user.Name, "telegram.settings", "", "token="+action, c.ip)
	writeJSON(w, http.StatusOK, s.st.TelegramSettings())
}

func (s *Server) handleTelegramTest(w http.ResponseWriter, r *http.Request, c *opCtx) {
	if s.telegramTestLimit.Reserve(c.user.Name) == nil {
		writeErr(w, http.StatusTooManyRequests, "Telegram test limit reached; wait a minute")
		return
	}
	tg := s.telegram()
	if tg == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Telegram is not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err := tg.Send(ctx, notify.Message{Server: "kodeblue hub", Kind: "test", Severity: "info", Title: "Test message from the kodeblue hub", Body: "Sent by " + c.user.Name + ". Server notifications will arrive in this chat."})
	s.st.Audit(c.user.Name, "telegram.test", "", fmt.Sprint(err == nil), c.ip)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

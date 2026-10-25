// Package llm is a minimal OpenAI-compatible chat client for kodeblue's
// single-shot calls (triage). Agent sessions go through the engine's own
// provider; this client exists so triage does not pay for a whole agent
// session to classify a handful of findings.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func New(baseURL, apiKey string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey, HTTP: &http.Client{Timeout: 120 * time.Second}}
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Request struct {
	Model          string    `json:"model"`
	Messages       []Message `json:"messages"`
	MaxTokens      int       `json:"max_tokens,omitempty"`
	Temperature    *float64  `json:"temperature,omitempty"`
	PromptCacheKey string    `json:"prompt_cache_key,omitempty"`
}

type Usage struct {
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	CachedTokens     int     `json:"cached_tokens"`
	CostUSD          float64 `json:"cost_usd"`
}

type Response struct {
	Content      string
	Reasoning    string
	FinishReason string
	Usage        Usage
	Model        string
}

// Chat sends one non-streaming completion.
func (c *Client) Chat(ctx context.Context, req Request) (*Response, error) {
	body, _ := json.Marshal(req)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * 2 * time.Second):
			}
		}
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		hreq.Header.Set("Content-Type", "application/json")
		hreq.Header.Set("Authorization", "Bearer "+c.APIKey)
		resp, err := c.HTTP.Do(hreq)
		if err != nil {
			lastErr = err
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("inference endpoint %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("inference endpoint %d: %s", resp.StatusCode, truncate(string(raw), 300))
		}
		var out struct {
			Model   string `json:"model"`
			Choices []struct {
				Message struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage struct {
				PromptTokens        int `json:"prompt_tokens"`
				CompletionTokens    int `json:"completion_tokens"`
				PromptTokensDetails struct {
					CachedTokens int `json:"cached_tokens"`
				} `json:"prompt_tokens_details"`
				Billing struct {
					BilledTotalUSD float64 `json:"billed_total_usd"`
				} `json:"billing"`
				Cost float64 `json:"cost"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}
		if len(out.Choices) == 0 {
			lastErr = fmt.Errorf("empty choices")
			continue
		}
		cost := out.Usage.Billing.BilledTotalUSD
		if cost == 0 {
			cost = out.Usage.Cost
		}
		return &Response{
			Content:      out.Choices[0].Message.Content,
			Reasoning:    out.Choices[0].Message.ReasoningContent,
			FinishReason: out.Choices[0].FinishReason,
			Model:        out.Model,
			Usage:        Usage{PromptTokens: out.Usage.PromptTokens, CompletionTokens: out.Usage.CompletionTokens, CachedTokens: out.Usage.PromptTokensDetails.CachedTokens, CostUSD: cost},
		}, nil
	}
	return nil, lastErr
}

// ExtractJSON pulls the first JSON object out of a model reply (models wrap
// JSON in prose or code fences more often than they should).
func ExtractJSON(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		rest = strings.TrimPrefix(rest, "json")
		if j := strings.Index(rest, "```"); j >= 0 {
			s = strings.TrimSpace(rest[:j])
		}
	}
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		ch := s[i]
		switch {
		case esc:
			esc = false
		case ch == '\\' && inStr:
			esc = true
		case ch == '"':
			inStr = !inStr
		case inStr:
		case ch == '{':
			depth++
		case ch == '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

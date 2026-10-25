package openai

import "strings"

// CacheCaps is a model's prompt-cache capability as published by the
// gateway's /v1/models. The client decides where cache boundaries are; the
// gateway translates the neutral marker for each upstream.
type CacheCaps struct {
	Supported  bool
	MaxMarkers int
}

// cacheCapsFor returns the published capability for a model, and whether the
// gateway published one at all (older gateways do not).
func (c *Client) cacheCapsFor(model string) (CacheCaps, bool) {
	if c.cacheCaps == nil {
		return CacheCaps{}, false
	}
	caps, ok := c.cacheCaps[strings.TrimSpace(model)]
	return caps, ok
}

// cacheBoundaryRole reports whether an API message can carry a cache marker:
// text-bearing system, user and tool messages.
func cacheBoundaryRole(role string) bool {
	return role == "system" || role == "user" || role == "tool"
}

// isRollingBoundary reports whether message i ends an input turn: a user
// message, or the last tool result of a consecutive tool-result batch (so a
// parallel tool batch is cached as a whole).
func isRollingBoundary(messages []apiMessage, i int) bool {
	switch messages[i].Role {
	case "user":
		return true
	case "tool":
		return i+1 == len(messages) || messages[i+1].Role != "tool"
	}
	return false
}

// applyCacheMarkers places up to caps.MaxMarkers neutral cache markers:
//  1. the system message (covers tools + system — the stable prefix),
//  2. the newest compaction summary (stable after compaction),
//  3. the newest input boundaries, newest first, until the budget is used.
//
// Every marker-eligible message is serialized as content parts whether or not
// it is marked this turn, so a message's bytes never change between calls
// when its marker moves.
func applyCacheMarkers(messages []apiMessage, caps CacheCaps, anchors []int) {
	if !caps.Supported || caps.MaxMarkers <= 0 {
		return
	}
	for i := range messages {
		if cacheBoundaryRole(messages[i].Role) {
			messages[i].Content = asContentParts(messages[i].Content)
		}
	}
	budget := min(caps.MaxMarkers, 4)
	marked := map[int]bool{}
	mark := func(i int) {
		if budget == 0 || i < 0 || i >= len(messages) || marked[i] {
			return
		}
		if markLastTextPart(&messages[i]) {
			marked[i] = true
			budget--
		}
	}
	if len(messages) > 0 && messages[0].Role == "system" {
		mark(0)
	}
	if len(anchors) > 0 {
		mark(anchors[len(anchors)-1])
	}
	for i := len(messages) - 1; i >= 0 && budget > 0; i-- {
		if isRollingBoundary(messages, i) {
			mark(i)
		}
	}
}

func asContentParts(content interface{}) interface{} {
	switch value := content.(type) {
	case string:
		if value == "" {
			return value
		}
		return []contentPart{{Type: "text", Text: value}}
	default:
		return content
	}
}

func markLastTextPart(message *apiMessage) bool {
	parts, ok := message.Content.([]contentPart)
	if !ok {
		return false
	}
	for j := len(parts) - 1; j >= 0; j-- {
		if parts[j].Type == "text" && strings.TrimSpace(parts[j].Text) != "" {
			parts[j].CacheControl = &apiCacheControl{Type: "ephemeral"}
			return true
		}
	}
	return false
}

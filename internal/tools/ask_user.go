package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

const (
	QuestionModeSingle = "single_select"
	QuestionModeMulti  = "multi_select"
)

type AskUserPrompt struct {
	SessionID internal.SessionID
	RunID     internal.RunID
	// Kind marks who asked. Empty means the model did, via this tool; the
	// continuation checkpoint sets internal.QuestionKindContinuation.
	Kind               string
	Title              string
	Question           string
	Mode               string
	Options            []string
	Custom             bool
	Recommended        string
	RecommendedChoices []string
}

type AskUserHandler func(ctx context.Context, prompts []AskUserPrompt) ([]internal.QuestionAnswer, error)

type askUserTool struct {
	handler AskUserHandler
}

func NewAskUser(handler AskUserHandler) Tool {
	return &askUserTool{handler: handler}
}

func (t *askUserTool) Name() internal.ToolName { return "ask_user" }

func (t *askUserTool) Description() string {
	return strings.TrimSpace(`
Ask the user one or more structured multiple-choice questions and wait for their answers. Use this when the user must choose or clarify something that changes the implementation.

options is a flat array of plain strings — one string per choice. Each string IS the label; do not wrap choices in objects.

CORRECT:   {"question":"Which database?","mode":"single_select","options":["SQLite","Postgres","MySQL"]}
WRONG:     {"options":[{"SQLite":""},{"Postgres":""}]}      // label must be the string itself, not an object key
WRONG:     {"options":[{"label":"SQLite"},{"label":"Postgres"}]}  // do not use {label:...} objects

To ask several questions at once, put one object per question in the top-level "questions" array — never nest a question inside another question's options:
  {"questions":[{"question":"Which DB?","mode":"single_select","options":["SQLite","Postgres","MySQL"]},{"question":"Which endpoints?","mode":"multi_select","options":["register","login","logout"]}]}

Rules: provide at least 2 options (2 is fine for yes/no or either/or questions). A free-text answer field is always shown automatically, so never add an "Other"/"Custom"/"Something else" option.`)
}

// structuralOptionKeys are field names that belong to a question object, not to
// an option. They guard the lenient {"<label>": ""} parsing below so a nested
// question is not mistaken for an option label.
var structuralOptionKeys = map[string]bool{
	"label": true, "title": true, "value": true, "text": true,
	"question": true, "mode": true, "options": true, "description": true,
	"recommended": true, "recommended_choices": true,
}

// labelFromOptionObject extracts an option label from the various object shapes
// models emit instead of a plain string. Returns false when the object looks
// like a nested question rather than a single option.
func labelFromOptionObject(object map[string]any) (string, bool) {
	// Explicit value-bearing keys, e.g. {"label":"SQLite"} or {"value":"SQLite"}.
	for _, key := range []string{"label", "title", "value", "text"} {
		if value, ok := object[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value), true
		}
	}
	// The label-as-key shape, e.g. {"SQLite + Prisma": ""}. Only accept a single
	// non-structural key so a real nested question still fails loudly.
	if len(object) == 1 {
		for key := range object {
			if !structuralOptionKeys[key] && strings.TrimSpace(key) != "" {
				return strings.TrimSpace(key), true
			}
		}
	}
	return "", false
}

type askUserOptionList []string

func (options *askUserOptionList) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("options must be a flat array of strings, e.g. [\"Option A\", \"Option B\", \"Option C\"]")
	}

	parsed := make([]string, 0, len(raw))
	for index, item := range raw {
		var label string
		if err := json.Unmarshal(item, &label); err == nil {
			label = strings.TrimSpace(label)
			if label == "" {
				return fmt.Errorf("options[%d] must not be empty", index)
			}
			parsed = append(parsed, label)
			continue
		}

		var object map[string]any
		if err := json.Unmarshal(item, &object); err == nil {
			if objectLabel, ok := labelFromOptionObject(object); ok {
				parsed = append(parsed, objectLabel)
				continue
			}
			return fmt.Errorf("options[%d] must be a plain string label like \"Use Postgres\", not an object. Write each option as a string (e.g. [\"A\", \"B\", \"C\"]); to ask another question put it in the top-level questions array instead", index)
		}

		return fmt.Errorf("options[%d] must be a plain string label like \"Use Postgres\"", index)
	}

	*options = parsed
	return nil
}

func (t *askUserTool) Parameters() json.RawMessage {
	questionSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"title":    map[string]any{"type": "string", "description": "Short title for the question"},
			"question": map[string]any{"type": "string", "description": "Question to ask the user. Keep it focused and actionable."},
			"mode": map[string]any{
				"type":        "string",
				"description": "Question mode: single_select | multi_select",
				"enum":        []string{QuestionModeSingle, QuestionModeMulti},
			},
			"options": map[string]any{
				"type":        "array",
				"description": "Flat array of plain strings — one string per choice, where each string IS the label (at least 2). Correct: [\"SQLite\", \"Postgres\", \"MySQL\"]. Wrong: [{\"SQLite\":\"\"}] or [{\"label\":\"SQLite\"}]. Never put objects or nested questions here; use the top-level questions array for multiple questions. A free-text field is shown automatically, so do not add an Other/Custom option.",
				"items":       map[string]any{"type": "string"},
			},
			"recommended": map[string]any{"type": "string", "description": "Recommended answer for single_select. It should be one of the provided options."},
			"recommended_choices": map[string]any{
				"type":        "array",
				"description": "Recommended answers for multi_select. Each recommended value should be one of the provided options.",
				"items":       map[string]any{"type": "string"},
			},
		},
		"required": []string{"question", "mode"},
	}

	return makeSchema(map[string]any{
		"title":    map[string]any{"type": "string", "description": "Short title for the question"},
		"question": map[string]any{"type": "string", "description": "Question to ask the user. Keep it focused and actionable."},
		"mode": map[string]any{
			"type":        "string",
			"description": "Question mode: single_select | multi_select",
			"enum":        []string{QuestionModeSingle, QuestionModeMulti},
		},
		"options": map[string]any{
			"type":        "array",
			"description": "Flat array of plain strings — one string per choice, where each string IS the label (at least 2). Correct: [\"SQLite\", \"Postgres\", \"MySQL\"]. Wrong: [{\"SQLite\":\"\"}] or [{\"label\":\"SQLite\"}]. Never put objects or nested questions here; use the top-level questions array for multiple questions. A free-text field is shown automatically, so do not add an Other/Custom option.",
			"items":       map[string]any{"type": "string"},
		},
		"recommended": map[string]any{"type": "string", "description": "Recommended answer for single_select. It should be one of the provided options."},
		"recommended_choices": map[string]any{
			"type":        "array",
			"description": "Recommended answers for multi_select. Each recommended value should be one of the provided options.",
			"items":       map[string]any{"type": "string"},
		},
		"questions": map[string]any{
			"type":        "array",
			"description": "Ask several questions in one call: one object per question. Shape: [{\"question\": \"...\", \"mode\": \"single_select\", \"options\": [\"A\", \"B\", \"C\"]}, {\"question\": \"...\", \"mode\": \"multi_select\", \"options\": [\"X\", \"Y\", \"Z\"]}]. Each question's options stay flat strings; never put one question inside another question's options.",
			"items":       questionSchema,
		},
	}, nil)
}

func (t *askUserTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	if t.handler == nil {
		return &Result{Content: "ask_user handler is not configured", IsError: true}, nil
	}

	type questionInput struct {
		Title              string            `json:"title"`
		Question           string            `json:"question"`
		Mode               string            `json:"mode"`
		Options            askUserOptionList `json:"options"`
		Recommended        string            `json:"recommended"`
		RecommendedChoices []string          `json:"recommended_choices"`
	}
	var params struct {
		Title              string            `json:"title"`
		Question           string            `json:"question"`
		Mode               string            `json:"mode"`
		Options            askUserOptionList `json:"options"`
		Recommended        string            `json:"recommended"`
		RecommendedChoices []string          `json:"recommended_choices"`
		Questions          []questionInput   `json:"questions"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return &Result{Content: "invalid ask_user arguments: " + err.Error() + ". Use either {\"question\":\"...\",\"mode\":\"single_select\",\"options\":[\"A\",\"B\",\"C\"]} or {\"questions\":[{\"question\":\"...\",\"mode\":\"multi_select\",\"options\":[\"A\",\"B\",\"C\"]}]}", IsError: true}, nil
	}

	questions := make([]questionInput, 0)
	if len(params.Questions) > 0 {
		questions = append(questions, params.Questions...)
	} else {
		questions = append(questions, questionInput{
			Title:              params.Title,
			Question:           params.Question,
			Mode:               params.Mode,
			Options:            params.Options,
			Recommended:        params.Recommended,
			RecommendedChoices: params.RecommendedChoices,
		})
	}
	if len(questions) == 0 {
		return &Result{Content: "at least one question is required", IsError: true}, nil
	}

	sessionID, runID, ok := ExecutionContextFromContext(ctx)
	if !ok {
		return &Result{Content: "ask_user requires session/run execution context", IsError: true}, nil
	}

	prompts := make([]AskUserPrompt, 0, len(questions))
	for i := range questions {
		q := questions[i]
		q.Mode = strings.TrimSpace(q.Mode)
		q.Question = strings.TrimSpace(q.Question)
		if q.Question == "" {
			return &Result{Content: fmt.Sprintf("question[%d] question is required", i), IsError: true}, nil
		}

		switch q.Mode {
		case QuestionModeSingle, QuestionModeMulti:
		default:
			return &Result{Content: fmt.Sprintf("question[%d] mode must be single_select or multi_select", i), IsError: true}, nil
		}

		if (q.Mode == QuestionModeSingle || q.Mode == QuestionModeMulti) && len(q.Options) < 2 {
			return &Result{Content: fmt.Sprintf("question[%d] select questions must include at least 2 options (2 is fine for yes/no or either/or); a free-text answer field is always available separately, so do not pad with filler options", i), IsError: true}, nil
		}
		if q.Mode == QuestionModeMulti && len(q.RecommendedChoices) > 0 {
			// keep as provided
		} else if q.Mode != QuestionModeMulti {
			q.RecommendedChoices = nil
		}

		prompts = append(prompts, AskUserPrompt{
			SessionID:          sessionID,
			RunID:              runID,
			Title:              q.Title,
			Question:           q.Question,
			Mode:               q.Mode,
			Options:            []string(q.Options),
			Custom:             true,
			Recommended:        q.Recommended,
			RecommendedChoices: q.RecommendedChoices,
		})
	}

	answers, err := t.handler(ctx, prompts)
	if err != nil {
		return &Result{Content: fmt.Sprintf("ask_user failed: %v", err), IsError: true}, nil
	}
	if len(answers) != len(prompts) {
		return &Result{Content: fmt.Sprintf("ask_user failed: expected %d answers, got %d", len(prompts), len(answers)), IsError: true}, nil
	}

	for i := range answers {
		answer := &answers[i]
		if answer.AnsweredAt.IsZero() {
			answer.AnsweredAt = time.Now()
		}
		if answer.Text == "" {
			switch answer.Mode {
			case QuestionModeSingle:
				if len(answer.Choices) > 0 {
					answer.Text = answer.Choices[0]
				}
			case QuestionModeMulti:
				if len(answer.Choices) > 0 {
					answer.Text = strings.Join(answer.Choices, ", ")
				}
			}
		}
	}

	var b []byte
	if len(answers) == 1 && len(params.Questions) == 0 {
		// Backward compatible single-question response.
		b, err = json.Marshal(answers[0])
	} else {
		b, err = json.Marshal(map[string]any{"answers": answers})
	}
	if err != nil {
		return &Result{Content: fmt.Sprintf("ask_user response marshal failed: %v", err), IsError: true}, nil
	}
	return &Result{
		Content: string(b),
		Metadata: map[string]any{
			"tool":      "ask_user",
			"questions": len(prompts),
			"answers":   len(answers),
		},
	}, nil
}

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FailureDiagnostic is an allowlisted summary, never an error body or request.
// Cause uses fixed descriptions inferred from the failure, so even a provider
// echoing a prompt in its message cannot send that prompt to events, logs or the UI.
type FailureDiagnostic struct {
	Cause        string `json:"provider_cause,omitempty"`
	Class        string `json:"failure_class,omitempty"`
	CauseType    string `json:"cause_type,omitempty"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	UpstreamCode string `json:"upstream_code,omitempty"`
	EndpointHost string `json:"endpoint_host,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
	// Attempt and MaxAttempts follow the owning retry layer: recovery counts
	// retries (0 is the initial request); Send counts requests starting at 1.
	Attempt         int    `json:"attempt"`
	MaxAttempts     int    `json:"max_attempts"`
	RetryElapsedMS  int64  `json:"retry_elapsed_ms"`
	RecoveryOutcome string `json:"recovery_outcome,omitempty"`
}

func (d FailureDiagnostic) Fields() map[string]any {
	fields := map[string]any{"provider_cause": d.Cause, "failure_class": d.Class, "cause_type": d.CauseType,
		"attempt": d.Attempt, "max_attempts": d.MaxAttempts, "retry_elapsed_ms": d.RetryElapsedMS}
	if d.HTTPStatus != 0 {
		fields["http_status"] = d.HTTPStatus
	}
	for key, value := range map[string]string{"upstream_code": d.UpstreamCode, "endpoint_host": d.EndpointHost, "request_id": d.RequestID, "recovery_outcome": d.RecoveryOutcome} {
		if value != "" {
			fields[key] = value
		}
	}
	return fields
}

// ResponseError preserves routing identifiers for HTTP-200 stream failures and
// transport failures while keeping errors.Is/As working on the underlying cause.
type ResponseError struct {
	Cause                   error
	EndpointHost, RequestID string
	HTTPStatus              int
}

func (e *ResponseError) Error() string { return e.Cause.Error() }
func (e *ResponseError) Unwrap() error { return e.Cause }

var diagnosticIdentifier = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)

func safeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if !diagnosticIdentifier.MatchString(value) || strings.Contains(value, "sk-") || strings.Contains(value, "im_") {
		return ""
	}
	return value
}
func endpointHost(u *url.URL) string {
	if u == nil {
		return ""
	}
	return safeEndpointHost(u.Hostname())
}

func safeEndpointHost(value string) string {
	host := strings.ToLower(value)
	if len(host) > 253 {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	return host
}
func responseIdentifiers(resp *http.Response) (string, string) {
	var host string
	if resp.Request != nil {
		host = endpointHost(resp.Request.URL)
	}
	for _, key := range []string{"x-request-id", "request-id", "x-amzn-requestid", "x-amzn-request-id", "x-openrouter-request-id"} {
		if id := safeRequestID(resp.Header.Get(key)); id != "" {
			return host, id
		}
	}
	return host, ""
}
func WrapResponseError(resp *http.Response, err error) error {
	if err == nil || resp == nil {
		return err
	}
	host, id := responseIdentifiers(resp)
	return &ResponseError{Cause: err, EndpointHost: host, RequestID: id, HTTPStatus: resp.StatusCode}
}

// Only known error codes (or numeric statuses) cross the privacy boundary.
func safeUpstreamCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if status, err := strconv.Atoi(code); err == nil && status >= 400 && status <= 599 {
		return strconv.Itoa(status)
	}
	switch code {
	case "rate_limit_exceeded", "rate_limit_error", "overloaded_error", "server_error", "internal_server_error", "api_error", "invalid_request_error", "authentication_error", "permission_error", "not_found_error", "insufficient_quota", "insufficient_credits", "quota_exceeded", "unknown_model", "model_not_found", "context_length_exceeded", "content_filter":
		return code
	}
	return ""
}

func bodyCode(body string, depth int) string {
	if depth > 2 {
		return ""
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &fields) != nil {
		return ""
	}
	for _, key := range []string{"code", "type", "upstream_status"} {
		var value string
		if json.Unmarshal(fields[key], &value) != nil {
			value = string(fields[key])
		}
		if code := safeUpstreamCode(value); code != "" {
			return code
		}
	}
	if code := bodyCode(string(fields["error"]), depth+1); code != "" {
		return code
	}
	var details string
	if json.Unmarshal(fields["details"], &details) == nil {
		return bodyCode(details, depth+1)
	}
	return ""
}

func DiagnoseFailure(err error) FailureDiagnostic {
	d := FailureDiagnostic{Class: "provider_error", Cause: "The model provider returned an error.", MaxAttempts: 1}
	if err == nil {
		return FailureDiagnostic{}
	}
	rootCause := err
	for errors.Unwrap(rootCause) != nil {
		rootCause = errors.Unwrap(rootCause)
	}
	d.CauseType = fmt.Sprintf("%T", rootCause)
	var api *APIStatusError
	var stream *StreamError
	var response *ResponseError
	var exhausted *RecoveryExhaustedError
	var stopped *RecoveryStoppedError
	text := err.Error() // inspected for known patterns only; never copied to fields
	if errors.As(err, &api) {
		d.HTTPStatus, d.EndpointHost, d.RequestID = api.StatusCode, api.EndpointHost, safeRequestID(api.RequestID)
		d.UpstreamCode = bodyCode(api.Body, 0)
		d.Attempt, d.MaxAttempts, d.RetryElapsedMS = api.Attempts, api.MaxAttempts, api.Elapsed.Milliseconds()
		if d.MaxAttempts == 0 {
			d.MaxAttempts = max(1, api.Attempts)
		}
	}
	if errors.As(err, &response) {
		d.EndpointHost, d.RequestID = response.EndpointHost, safeRequestID(response.RequestID)
		if d.HTTPStatus == 0 {
			d.HTTPStatus = response.HTTPStatus
		}
	}
	if errors.As(err, &stream) {
		d.UpstreamCode = safeUpstreamCode(stream.Code)
	}
	if errors.As(err, &exhausted) {
		d.Attempt, d.MaxAttempts, d.RetryElapsedMS, d.RecoveryOutcome = exhausted.Attempt, exhausted.MaxAttempts, exhausted.Elapsed.Milliseconds(), "exhausted"
	}
	if errors.As(err, &stopped) {
		d.Attempt, d.MaxAttempts, d.RetryElapsedMS, d.RecoveryOutcome = stopped.Attempt, stopped.MaxAttempts, stopped.Elapsed.Milliseconds(), "stopped"
	}
	lower := strings.ToLower(text)
	code := d.UpstreamCode
	status := d.HTTPStatus
	// A streamed status describes the upstream; HTTPStatus still describes the
	// successful gateway handshake, so keep both rather than relabeling HTTP 200.
	if n, e := strconv.Atoi(code); e == nil {
		status = n
	}
	has := func(parts ...string) bool {
		for _, p := range parts {
			if strings.Contains(lower, p) {
				return true
			}
		}
		return false
	}
	set := func(class, cause string) { d.Class, d.Cause = class, cause }
	var netErr net.Error
	switch {
	case errors.Is(err, context.Canceled):
		set("cancelled", "The request was cancelled.")
	case has("monthly spend limit reached"):
		set("quota_exceeded", "The model provider rejected the request: monthly spend limit reached.")
	case has("quota exceeded", "insufficient credit", "insufficient balance", "insufficient funds", "out of credit") || code == "insufficient_quota" || code == "insufficient_credits" || code == "quota_exceeded":
		set("quota_exceeded", "The model provider's quota or credit balance is exhausted.")
	case status == 401 || code == "authentication_error":
		set("authentication", "The model provider rejected the credentials.")
	case status == 403 || code == "permission_error" || has("not authorized", "is disabled", "provider not available"):
		set("permission", "The model provider denied access to this model.")
	case code == "unknown_model" || code == "model_not_found" || has("unknown_model", "unknown model"):
		set("unknown_model", "The model provider rejected an unknown model.")
	case code == "context_length_exceeded":
		set("context_length", "The request exceeds the model's context limit.")
	case code == "content_filter" || has("finish_reason=content_filter"):
		set("content_filter", "The model provider's content filter stopped the response.")
	case status == 429 || code == "rate_limit_exceeded" || code == "rate_limit_error" || has("rate-limited", "rate limited", "rate limit exceeded", "too many requests"):
		set("rate_limit", "The model provider is rate limiting requests for this model right now.")
	case code == "overloaded_error" || status == 529:
		set("overloaded", "The model provider is overloaded.")
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) || has("idle timeout", "i/o timeout"):
		set("timeout", "The connection to the model provider timed out.")
	case status == 408 || status == 504:
		set("timeout", fmt.Sprintf("The model provider timed out (HTTP %d).", status))
	case status >= 500 || has("upstream unavailable", "service unavailable", "temporarily unavailable"):
		set("unavailable", "The model provider is temporarily unavailable.")
	case has("connection reset"):
		set("connection_reset", "The connection to the model provider was reset.")
	case has("connection refused"):
		set("connection_refused", "The model provider refused the connection.")
	case has("broken pipe"):
		set("broken_pipe", "The connection to the model provider closed while sending the request.")
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || has("stream truncated", "stream eof"):
		set("stream_truncated", "The model provider's response ended before it completed.")
	case has("no such host"):
		set("dns", "The model provider's endpoint could not be resolved.")
	case has("tls:", "x509:"):
		set("tls", "The secure connection to the model provider failed.")
	case has("finish_reason=error"):
		set("upstream_stream_error", "The model provider ended the response with an error.")
	case code == "invalid_request_error" || (status >= 400 && status < 500):
		set("invalid_request", "The model provider rejected the request.")
	case errors.As(err, &stream):
		set("upstream_stream_error", "The model provider returned an upstream stream error.")
	case errors.As(err, &netErr):
		set("connection", "The connection to the model provider failed.")
	}
	if d.HTTPStatus >= 400 && !strings.Contains(d.Cause, "HTTP") {
		d.Cause = strings.TrimSuffix(d.Cause, ".") + fmt.Sprintf(" (HTTP %d).", d.HTTPStatus)
	}
	d.EndpointHost = safeEndpointHost(d.EndpointHost)
	return d
}

// RecoveryStoppedError includes the retry outcome without masking the cause.
type RecoveryStoppedError struct {
	Cause                error
	Attempt, MaxAttempts int
	Elapsed              time.Duration
}

func (e *RecoveryStoppedError) Error() string { return e.Cause.Error() }
func (e *RecoveryStoppedError) Unwrap() error { return e.Cause }

func FailureFields(err error) map[string]any {
	fields := DiagnoseFailure(err).Fields()
	fields["reason"] = FailureReason(err)
	return fields
}

package provider

import (
	"strings"

	"github.com/Problem99-io/kodeblue/internal"
)

// AttachmentDisabledReason is the phrase used to tell a model why an attachment
// it was sent is not actually present.
const AttachmentDisabledReason = "PDF attachments are temporarily disabled"

// IsDisabledAttachment reports whether an attachment must never be serialized
// into a provider request, whatever the route or the model's own capabilities.
//
// PDFs are the only entry today. On OpenRouter a `file` part is handed to the
// file-parser plugin, which bills its default `mistral-ocr` engine per page
// unless the request declares an engine — a cost this product neither chooses
// nor meters. Native Anthropic has the same gap through its `document` block.
// The composer and the task-message API both refuse PDFs already; this is the
// last gate, so the guarantee holds for any caller that reaches a provider.
func IsDisabledAttachment(att internal.Attachment) bool {
	if strings.EqualFold(strings.TrimSpace(att.MediaType), "application/pdf") {
		return true
	}
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(att.FileName)), ".pdf")
}

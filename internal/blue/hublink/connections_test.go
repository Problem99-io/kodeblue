package hublink

import (
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func TestCheckSettingsConnections(t *testing.T) {
	kind := hubproto.ConnectionKinds[0]
	ok := []hubproto.Connection{
		{ID: "main", Kind: kind, ViaHub: true},                                   // through the hub: no endpoint, no key
		{ID: "old", Kind: kind, BaseURL: "https://api.example.com", APIKey: "k"}, // an older hub
	}
	if err := checkSettings(&hubproto.Settings{Connections: ok}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []hubproto.Connection{
		{ID: "main", Kind: kind},                           // neither an endpoint nor via the hub
		{ID: "main", Kind: kind, BaseURL: "file:///etc/x"}, // not http(s)
		{ID: "../x", Kind: kind, ViaHub: true},             // bad id
		{ID: "main", Kind: "something-else", ViaHub: true}, // unknown kind
	} {
		if checkSettings(&hubproto.Settings{Connections: []hubproto.Connection{bad}}) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

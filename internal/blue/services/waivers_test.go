package services

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
)

// A gap nobody can close must not come back after every resolve: a waived
// check is not missing, the case resolves, and the inventory still shows the
// check as waived (not covered).
func TestWaiverResolvesAndKeepsCaseClosed(t *testing.T) {
	st := openStore(t)
	ctx := Context{Coverage: sensorsOK("process")}
	if opened, _ := Sync(st, Assess([]sensors.Service{redis}, ctx)); len(opened) != 1 {
		t.Fatalf("opened %d", len(opened))
	}
	if err := Waive(st, "redis-server", []string{Health}, "x", "operator", 0); err == nil {
		t.Fatal("a waiver needs a real reason")
	}
	if err := Waive(st, "redis-server", []string{"access-log"}, "kodeblue cannot reach the port from here", "operator", 0); err == nil {
		t.Fatal("only known checks can be waived")
	}
	if err := Waive(st, "redis-server", []string{Health}, "kodeblue cannot reach redis's port from its namespace", "operator", 0); err != nil {
		t.Fatal(err)
	}
	ctx.Waivers = LoadWaivers(st)
	inv := Assess([]sensors.Service{redis}, ctx)
	r := inv.Services[0]
	if !r.Covered() || r.Checks[0].Waived == nil || len(r.Checks[0].By) != 0 {
		t.Fatalf("waived check: %+v", r)
	}
	if _, resolved := Sync(st, inv); len(resolved) != 1 || !strings.Contains(resolved[0].Summary, "waived by operator") {
		t.Fatalf("resolved: %+v", resolved)
	}
	// The next passes do not reopen it.
	for range 3 {
		if opened, _ := Sync(st, Assess([]sensors.Service{redis}, ctx)); len(opened) != 0 {
			t.Fatalf("reopened a waived gap: %+v", opened)
		}
	}
	// Removing the waiver asks for the check again.
	if n, _ := Unwaive(st, "redis-server", nil, "operator"); n != 1 {
		t.Fatalf("unwaive: %d", n)
	}
	ctx.Waivers = LoadWaivers(st)
	if opened, _ := Sync(st, Assess([]sensors.Service{redis}, ctx)); len(opened) != 1 {
		t.Fatalf("an unwaived gap opens a case again: %+v", opened)
	}
}

func TestWaiverExpires(t *testing.T) {
	st := openStore(t)
	_ = Waive(st, "redis-server", []string{Health}, "kodeblue cannot reach redis's port from its namespace", "operator", 1)
	w := LoadWaivers(st)
	got := w["redis-server"][Health]
	if time.Until(got.ExpiresAt) > 25*time.Hour {
		t.Fatalf("expiry: %v", got.ExpiresAt)
	}
	got.ExpiresAt = time.Now().Add(-time.Minute)
	w["redis-server"][Health] = got
	_ = saveWaivers(st, w)
	if len(LoadWaivers(st)) != 0 {
		t.Fatal("an expired waiver must not count")
	}
	_ = Waive(st, "redis-server", []string{Health}, "kodeblue cannot reach redis's port from its namespace", "operator", 5000)
	if d := time.Until(LoadWaivers(st)["redis-server"][Health].ExpiresAt); d > (MaxWaiverDays+1)*24*time.Hour {
		t.Fatalf("waiver longer than the cap: %v", d)
	}
}

// sshd and dockerd share the host's network: the listener and outbound
// sensors cover their network check. A container in its own namespace, or
// any other host service, still needs its own sockets monitor.
func TestHostNetworkServicesUseTheNetworkSensors(t *testing.T) {
	dockerd := sensors.Service{Name: "docker", Unit: "docker.service", State: sensors.ServiceRunning, Exes: []string{"/usr/bin/dockerd"},
		Listen: []sensors.Port{{Proto: "tcp", Port: 2376, Address: "0.0.0.0"}}}
	ctx := Context{Coverage: sensorsOK("process", "auth", "listener", "outbound")}
	inv := Assess([]sensors.Service{sshd, dockerd, nginx, app}, ctx)
	for _, name := range []string{"ssh", "docker"} {
		r := find(t, inv, name)
		if slices.Contains(r.Missing, Network) {
			t.Fatalf("%s network should be the sensors': %+v", name, r)
		}
	}
	if !slices.Contains(find(t, inv, "nginx").Missing, Network) {
		t.Fatal("nginx is not a host-network service: it still needs a sockets monitor")
	}
	if !slices.Contains(find(t, inv, "container 0123456789ab").Missing, Network) {
		t.Fatal("a container in its own namespace still needs a sockets monitor")
	}
	// With either network sensor off, the gap is real again.
	ctx.Coverage = sensorsOK("process", "auth", "listener")
	if !slices.Contains(find(t, Assess([]sensors.Service{sshd}, ctx), "ssh").Missing, Network) {
		t.Fatal("without the outbound sensor nothing watches sshd's connections")
	}
}

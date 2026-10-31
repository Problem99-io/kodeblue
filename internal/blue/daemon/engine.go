package daemon

import (
	"context"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/runtime"
)

// agentEngine is the part of the agent runtime the daemon drives;
// *runtime.Engine implements it.
type agentEngine interface {
	Start(ctx context.Context) error
	Stop()
	Alive() bool
	StartSession(ctx context.Context, agent, provider, model, message string) (*runtime.Session, error)
	SessionBusy(ctx context.Context, sessionID string) (bool, error)
	FollowUp(ctx context.Context, s *runtime.Session, message string) (*runtime.Session, error)
	Steer(ctx context.Context, s *runtime.Session, message string) error
	Abort(ctx context.Context, sessionID string) error
	WaitSession(ctx context.Context, s *runtime.Session, timeout time.Duration) runtime.Outcome
	Wait(ctx context.Context, s *runtime.Session, timeout time.Duration) runtime.Outcome
	SessionCost(ctx context.Context, sessionID string) (usd float64, in, out, cached int)
	Transcript(ctx context.Context, sessionID string, running bool) ([]hubproto.Turn, error)
}

// engineGen is one running engine. Its ctx ends when the engine is replaced
// or stopped, so work started on it stops waiting on a process that is gone.
type engineGen struct {
	eng    agentEngine
	ctx    context.Context
	cancel context.CancelFunc
}

// engine returns the running engine, or nil when the model layer is off or
// the engine is down (it is being restarted).
func (d *Daemon) engine() agentEngine {
	d.engMu.RLock()
	defer d.engMu.RUnlock()
	if d.eng == nil {
		return nil
	}
	return d.eng.eng
}

// engineFor returns the running engine (nil if none) and a context that ends
// with ctx or when that engine goes away. Call release when done.
func (d *Daemon) engineFor(ctx context.Context) (e agentEngine, ectx context.Context, release func()) {
	d.engMu.RLock()
	g := d.eng
	d.engMu.RUnlock()
	if g == nil {
		return nil, ctx, func() {}
	}
	c, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(g.ctx, cancel)
	return g.eng, c, func() { stop(); cancel() }
}

// setEngine installs e (nil: none), ends the previous engine's context and
// returns that engine for the caller to stop.
func (d *Daemon) setEngine(e agentEngine) agentEngine {
	var g *engineGen
	if e != nil {
		ctx, cancel := context.WithCancel(context.Background())
		g = &engineGen{eng: e, ctx: ctx, cancel: cancel}
	}
	d.engMu.Lock()
	old := d.eng
	d.eng = g
	d.engMu.Unlock()
	if old == nil {
		return nil
	}
	old.cancel()
	return old.eng
}

// startEngine starts a new engine and installs it in place of any other.
func (d *Daemon) startEngine(ctx context.Context) error {
	e := d.newEngine()
	if err := e.Start(ctx); err != nil {
		e.Stop() // a child that never became healthy must not linger
		return err
	}
	if old := d.setEngine(e); old != nil {
		old.Stop()
	}
	return nil
}

func (d *Daemon) stopEngine() {
	if old := d.setEngine(nil); old != nil {
		old.Stop()
	}
}

// superviseEngine restarts the engine when it died, and keeps trying (with
// backoff) when a start failed: one failure must not leave the server
// without agents until the service restarts. Sessions running on a dead
// engine see its context end and hand their incidents to a human.
func (d *Daemon) superviseEngine(ctx context.Context) {
	if !d.modelsOn || ctx.Err() != nil {
		return
	}
	if e := d.engine(); e != nil {
		if e.Alive() {
			return
		}
		d.log.Warn("engine not healthy; restarting")
		d.st.Journal("kodeblue", "engine.restart", "engine not healthy")
		d.stopEngine()
	} else if time.Now().Before(d.engRetryAt) {
		return
	}
	if err := d.startEngine(ctx); err != nil {
		d.engBackoff = min(max(2*d.engBackoff, d.engMinBackoff), 15*time.Minute)
		d.engRetryAt = time.Now().Add(d.engBackoff)
		d.log.Error("engine start failed; agent sessions unavailable until it starts", "error", err, "retry_in", d.engBackoff)
		return
	}
	d.engBackoff, d.engRetryAt = 0, time.Time{}
	d.log.Info("engine started")
}

// engineLoop supervises the engine on its own goroutine: a restart can take
// a minute and must not hold up sweeps.
func (d *Daemon) engineLoop(ctx context.Context) {
	t := time.NewTicker(d.engCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.superviseEngine(ctx)
		}
	}
}

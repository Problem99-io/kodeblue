package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
)

// inferenceCmd shows or sets the model endpoint ([inference] in the config)
// and its key. Without flags it prints the current endpoint and exits 1 when
// the model layers are off, so the installer can tell whether to ask for one.
// Setting either restarts kodeblue, so the change applies at once.
func inferenceCmd(cfg config.Config, baseURL, provider, model, keyFile string) {
	if baseURL == "" && provider == "" && model == "" && keyFile == "" {
		in := cfg.Inference
		fmt.Printf("endpoint  %s\nprovider  %s\ntriage    %s\nagents    %s\n", orNone(in.BaseURL), orNone(in.Provider), orNone(in.TriageModel), orNone(in.AgentModel))
		if in.EscalationModel != "" {
			fmt.Printf("critical  %s\n", in.EscalationModel)
		}
		if err := cfg.ModelsReady(); err != nil {
			fmt.Printf("models    off (%v)\n", err)
			os.Exit(1)
		}
		fmt.Println("models    on")
		return
	}
	if os.Geteuid() != 0 {
		fatal(errors.New("setting the model endpoint must run as root (it writes the config): use sudo"))
	}
	if baseURL != "" || provider != "" || model != "" {
		if err := writeInference(cfg, baseURL, provider, model); err != nil {
			fatal(err)
		}
		fmt.Println("model endpoint saved")
	}
	if keyFile != "" {
		key, err := readKey(keyFile)
		if err == nil {
			err = writeKey(cfg.Inference.APIKeyFile, key)
		}
		if err != nil {
			fatal(err)
		}
		fmt.Println("API key saved in " + cfg.Inference.APIKeyFile)
		if strings.TrimSpace(cfg.Inference.APIKey) != "" {
			fmt.Fprintln(os.Stderr, "warning: [inference] api_key in "+cfg.Path()+" takes precedence over the key file: remove it to use the new key")
		}
	}
	restartService()
}

// readKey reads the API key from a file, or from stdin for "-", asking for it
// without echo when stdin is a terminal.
func readKey(f string) (string, error) {
	var b []byte
	var err error
	if f == "-" {
		if fi, e := os.Stdin.Stat(); e == nil && fi.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprint(os.Stderr, "API key for the model endpoint: ")
			off := exec.Command("stty", "-echo")
			off.Stdin = os.Stdin
			_ = off.Run()
			echoOn := func() {
				on := exec.Command("stty", "echo")
				on.Stdin = os.Stdin
				_ = on.Run()
				fmt.Fprintln(os.Stderr)
			}
			// Ctrl-C must not leave the terminal without echo.
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			done := make(chan struct{})
			go func() {
				select {
				case <-sig:
					echoOn()
					os.Exit(130)
				case <-done:
				}
			}()
			defer func() { close(done); signal.Stop(sig); echoOn() }()
			line, e := bufio.NewReader(os.Stdin).ReadString('\n')
			b, err = []byte(line), e
			if errors.Is(err, io.EOF) {
				err = nil
			}
		} else {
			b, err = io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		}
	} else {
		b, err = os.ReadFile(f)
	}
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(b))
	if key == "" || strings.ContainsAny(key, "\r\n") {
		return "", errors.New("the API key must be one non-empty line")
	}
	return key, nil
}

// writeKey stores the key as root:kodeblue 0640, the way the installer does:
// a new file created beside the target (never following a link planted
// there), synced, then renamed over it.
func writeKey(path, key string) error {
	if path == "" {
		return errors.New("[inference] api_key_file is not set in the config")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".inference-key-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // after a successful rename there is nothing left to remove
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return err
	}
	if g, err := user.LookupGroup("kodeblue"); err == nil {
		gid, _ := strconv.Atoi(g.Gid)
		if err := f.Chown(0, gid); err != nil {
			f.Close()
			return err
		}
	} else if os.Geteuid() == 0 {
		f.Close()
		return errors.New("no kodeblue group: is kodeblue installed? (the daemon could not read the key)")
	}
	if _, err := f.WriteString(key + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// restartService asks a running kodeblue to restart with the new endpoint or
// key once no agent session or learning run is in progress (systemctl reload
// sends SIGHUP, see kodeblue.service), so an
// incident under way is not cut short. A stopped kodeblue, or the installer
// (KODEBLUE_NO_RESTART), uses them when it starts.
func restartService() {
	if os.Getenv("KODEBLUE_NO_RESTART") != "" {
		return
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if exec.Command("systemctl", "is-active", "--quiet", "kodeblue.service").Run() != nil {
			return
		}
		if out, err := exec.Command("systemctl", "reload", "kodeblue.service").CombinedOutput(); err == nil {
			fmt.Println("kodeblue restarts to use it as soon as no agent session or learning run is in progress")
			return
		} else {
			fmt.Fprintf(os.Stderr, "could not signal kodeblue: %v %s\n", err, strings.TrimSpace(string(out)))
		}
	}
	fmt.Println("restart kodeblue to use it (sudo systemctl restart kodeblue)")
}

// writeInference rewrites the [inference] table with the given endpoint,
// provider label and model (used for triage and agents), keeping the key
// settings and any escalation model already configured.
func writeInference(cfg config.Config, baseURL, provider, model string) error {
	in := cfg.Inference
	if baseURL != "" {
		u, err := url.Parse(baseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("--url must be an http(s) URL, e.g. https://api.example.com (got %q)", baseURL)
		}
		in.BaseURL = config.NormalizeBaseURL(baseURL)
	}
	if provider != "" {
		in.Provider = provider
	}
	if model != "" {
		in.TriageModel, in.AgentModel = model, model
	}
	if in.BaseURL == "" || in.AgentModel == "" {
		return errors.New("set both --url and --model")
	}
	q := strconv.Quote
	var b strings.Builder
	b.WriteString("[inference]\n# Any OpenAI-compatible endpoint: kodeblue calls {base_url}/v1/chat/completions.\n")
	fmt.Fprintf(&b, "base_url = %s\n", q(in.BaseURL))
	if in.APIKey != "" {
		fmt.Fprintf(&b, "api_key = %s\n", q(in.APIKey))
	}
	fmt.Fprintf(&b, "api_key_file = %s   # root:kodeblue 0640, one line\n", q(in.APIKeyFile))
	fmt.Fprintf(&b, "provider = %s\ntriage_model = %s\nagent_model = %s\n", q(in.Provider), q(in.TriageModel), q(in.AgentModel))
	if in.EscalationModel != "" {
		fmt.Fprintf(&b, "escalation_provider = %s\nescalation_model = %s\n", q(in.EscalationProvider), q(in.EscalationModel))
	}
	return replaceSection(cfg.Path(), "inference", b.String())
}

func orNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

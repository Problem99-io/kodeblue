// kodeblue-hub is the central console for a fleet of kodeblue servers.
//
//	kodeblue-hub serve [flags]                start the hub
//	kodeblue-hub user add|del|list <name>     operator accounts (password read from stdin)
//	kodeblue-hub server add <name>            create a server + one-time install command
//	kodeblue-hub fleet set|clear|status <setting>   fleet settings (value on stdin):
//	    inference-url, inference-model, inference-provider, inference-key
//	        the model endpoint handed to servers at enrollment (any OpenAI-compatible API)
//	    slack-webhook
//	        the fleet's Slack channel; the hub posts all notifications
//	kodeblue-hub pin                          print the TLS public-key pin servers use
//	kodeblue-hub version
//
// Servers always dial in. Each one enrolls with a one-time token and then
// authenticates with its own API key; the hub stores only hashes of both.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/hub"
	"github.com/Problem99-io/kodeblue/internal/research"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	data := fs.String("data", envOr("KODEBLUE_HUB_DATA", "/var/lib/kodeblue-hub"), "data directory")
	listen := fs.String("listen", envOr("KODEBLUE_HUB_LISTEN", ":8443"), "listen address")
	certFile := fs.String("tls-cert", os.Getenv("KODEBLUE_HUB_TLS_CERT"), "TLS certificate (PEM)")
	keyFile := fs.String("tls-key", os.Getenv("KODEBLUE_HUB_TLS_KEY"), "TLS private key (PEM)")
	disableIP := fs.Bool("disable-ip-enrichment", envOr("KODEBLUE_HUB_DISABLE_IP_ENRICHMENT", "") == "1", "disable third-party IP enrichment regardless of console settings")
	researchEnabled := fs.Bool("behavioral-research", os.Getenv("KODEBLUE_HUB_BEHAVIORAL_RESEARCH") == "1", "enable the experimental, independent behavioral evidence store")
	selfSigned := fs.Bool("self-signed", envOr("KODEBLUE_HUB_SELF_SIGNED", "") == "1", "generate a self-signed certificate in <data>/tls; servers pin its public key")
	behindProxy := fs.Bool("behind-proxy", envOr("KODEBLUE_HUB_BEHIND_PROXY", "") == "1", "plain HTTP behind a TLS-terminating reverse proxy (believes its X-Forwarded-For)")
	trustedProxies := fs.String("trusted-proxy", os.Getenv("KODEBLUE_HUB_TRUSTED_PROXIES"), "with --behind-proxy: addresses/CIDRs of the proxies whose X-Forwarded-For is believed (default loopback)")
	consoleAllow := fs.String("console-allow", os.Getenv("KODEBLUE_HUB_CONSOLE_ALLOW"), "addresses/CIDRs allowed to reach the console and operator API, e.g. 10.66.0.0/24,203.0.113.7 (default: everyone); servers can always enroll and sync")
	endpointAllow := fs.String("endpoint-allow", os.Getenv("KODEBLUE_HUB_ENDPOINT_ALLOW"), "addresses/CIDRs the hub may reach model endpoints at although they are loopback, link-local or cloud metadata, e.g. 127.0.0.1 for a model gateway on the hub's own host (private LAN ranges are always allowed)")
	publicURL := fs.String("public-url", os.Getenv("KODEBLUE_HUB_PUBLIC_URL"), "URL servers and browsers use to reach the hub, e.g. https://hub.example.com")
	dist := fs.String("dist", os.Getenv("KODEBLUE_HUB_DIST"), "directory with install.sh and release tarballs (default <data>/dist)")
	enrollTTL := fs.Duration("enroll-ttl", 2*time.Hour, "lifetime of one-time enrollment tokens")
	httpListen := fs.String("http-listen", os.Getenv("KODEBLUE_HUB_HTTP_LISTEN"), "extra plain-HTTP listener for the console, loopback only (e.g. 127.0.0.1:8080 for an SSH tunnel)")
	var pos []string
	for len(args) > 0 {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	if *dist == "" {
		*dist = filepath.Join(*data, "dist")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	switch cmd {
	case "serve":
		serve(logger, *data, *listen, *httpListen, *certFile, *keyFile, *selfSigned, *behindProxy, *trustedProxies, *consoleAllow, *endpointAllow, *publicURL, *dist, *enrollTTL, *disableIP, *researchEnabled)
	case "user":
		st := mustStore(*data)
		defer st.Close()
		userCmd(st, pos)
	case "server":
		st := mustStore(*data)
		defer st.Close()
		if len(pos) < 2 || pos[0] != "add" || *publicURL == "" {
			fatal(errors.New("usage: kodeblue-hub server add <name> --public-url https://…"))
		}
		pin, ok := servedPin(st)
		if !ok {
			fatal(errors.New("the hub has never run: start kodeblue-hub serve first, so the install command pins the certificate it serves (or none)"))
		}
		srv, tok, err := st.CreateServer(strings.Join(pos[1:], " "), "cli", *enrollTTL)
		if err != nil {
			fatal(err)
		}
		st.Audit("cli", "server.create", srv.ID, srv.Name, "")
		s := hub.NewServer(hub.Options{PublicURL: *publicURL, Pin: pin, DistDir: *dist}, st, logger)
		r, _ := http.NewRequest("GET", "https://localhost/", nil)
		fmt.Printf("server %s (%s); token valid until %s\n\nRun on the server:\n  %s\n", srv.Name, srv.ID, srv.EnrollExpires.Format(time.RFC3339), s.InstallCommand(r, tok))
	case "fleet", "secret": // "secret" is the old name
		st := mustStore(*data)
		defer st.Close()
		fleetCmd(st, pos)
	case "pin":
		pin := currentPin(*data, *certFile)
		if pin == "" {
			fatal(errors.New("no certificate found (use --tls-cert, or run serve --self-signed once)"))
		}
		fmt.Println(pin)
	case "version":
		fmt.Println("kodeblue-hub", hubproto.Version)
	default:
		usage()
		os.Exit(2)
	}
}

func serve(logger *slog.Logger, data, listen, httpListen, certFile, keyFile string, selfSigned, behindProxy bool, trustedProxies, consoleAllow, endpointAllow, publicURL, dist string, enrollTTL time.Duration, disableIP bool, researchEnabled bool) {
	opt := hub.Options{DisableIPEnrichment: disableIP, DataDir: data, DistDir: dist, PublicURL: publicURL, BehindProxy: behindProxy, EnrollTTL: enrollTTL}
	var err error
	if opt.TrustedProxies, err = hub.ParsePrefixes(trustedProxies); err != nil {
		fatal(fmt.Errorf("--trusted-proxy: %w", err))
	}
	if len(opt.TrustedProxies) > 0 && !behindProxy {
		fatal(errors.New("--trusted-proxy needs --behind-proxy"))
	}
	if opt.ConsoleAllow, err = hub.ParsePrefixes(consoleAllow); err != nil {
		fatal(fmt.Errorf("--console-allow: %w", err))
	}
	if opt.EndpointAllow, err = hub.ParsePrefixes(endpointAllow); err != nil {
		fatal(fmt.Errorf("--endpoint-allow: %w", err))
	}
	st := mustStore(data)
	defer st.Close()
	if researchEnabled {
		r, err := research.Open(filepath.Join(data, "research"), research.DefaultLimits())
		if err != nil {
			fatal(fmt.Errorf("behavioral research: %w", err))
		}
		defer r.Close()
		opt.Research = r
	}
	if publicURL != "" {
		if _, err := hubproto.CheckURL(publicURL); err != nil {
			fatal(fmt.Errorf("--public-url: %w", err))
		}
	}
	var tlsCfg *tls.Config
	switch {
	case certFile != "" || keyFile != "":
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			fatal(err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	case selfSigned:
		cert, err := selfSignedCert(data, publicURL)
		if err != nil {
			fatal(err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		opt.Pin = hubproto.Pin(leaf)
		logger.Info("self-signed certificate; servers pin its public key", "pin", opt.Pin)
	case behindProxy:
		if publicURL == "" || !strings.HasPrefix(publicURL, "https://") {
			fatal(errors.New("--behind-proxy needs --public-url https://… (the proxy must terminate TLS)"))
		}
	default:
		host, _, err := net.SplitHostPort(listen)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			fatal(errors.New("refusing plain HTTP on a non-loopback address: use --tls-cert/--tls-key, --self-signed, or --behind-proxy (or --listen 127.0.0.1:PORT for local testing)"))
		}
	}
	if err := recordServedPin(st, opt.Pin); err != nil {
		fatal(err)
	}
	opt.SecureCookies = tlsCfg != nil || behindProxy
	if len(opt.ConsoleAllow) > 0 {
		logger.Info("console limited to listed addresses", "allow", consoleAllow)
	}
	srv := hub.NewServer(opt, st, logger)
	if err := srv.Check(); err != nil {
		logger.Warn(err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Janitor(ctx)
	go srv.NotificationForwarder(ctx)
	go srv.ResearchMaintenance(ctx)
	srv.StartWarRoom(ctx)
	hs := &http.Server{Addr: listen, Handler: srv.Handler(), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	var local *http.Server
	if httpListen != "" {
		host, _, err := net.SplitHostPort(httpListen)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			fatal(errors.New("--http-listen must be a loopback address such as 127.0.0.1:8080"))
		}
		local = &http.Server{Addr: httpListen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
		go func() {
			logger.Info("local console listener (plain HTTP, loopback only)", "addr", httpListen)
			if err := local.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("local listener", "error", err)
			}
		}()
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
		if local != nil {
			_ = local.Shutdown(sctx)
		}
	}()
	logger.Info("kodeblue hub listening", "addr", listen, "tls", tlsCfg != nil, "behind_proxy", behindProxy, "public_url", publicURL, "dist", dist)
	if tlsCfg != nil {
		err = hs.ListenAndServeTLS("", "")
	} else {
		err = hs.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
}

// selfSignedCert loads or creates <data>/tls/{cert,key}.pem. The key is kept
// across restarts so the pin servers hold stays valid.
func selfSignedCert(data, publicURL string) (tls.Certificate, error) {
	dir := filepath.Join(data, "tls")
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "kodeblue-hub"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if u, err := url.Parse(publicURL); err == nil && u.Hostname() != "" {
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, u.Hostname())
		}
	}
	if h, err := os.Hostname(); err == nil {
		tpl.DNSNames = append(tpl.DNSNames, h)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// servedPinKey holds the pin serve last served, or "none" when it served no
// self-signed certificate (--tls-cert, --behind-proxy, plain loopback), so
// server add never hands out a pin for a certificate the hub has left
// behind in <data>/tls.
const servedPinKey = "served_pin"

func recordServedPin(st *hub.Store, pin string) error {
	if pin == "" {
		pin = "none"
	}
	return st.SetSetting(servedPinKey, pin)
}

// servedPin returns the pin serve last served ("" when not self-signed), and
// false when serve has never run.
func servedPin(st *hub.Store) (string, bool) {
	switch v := st.Setting(servedPinKey); v {
	case "":
		return "", false
	case "none":
		return "", true
	default:
		return v, true
	}
}

func currentPin(data, certFile string) string {
	if certFile == "" {
		certFile = filepath.Join(data, "tls", "cert.pem")
	}
	b, err := os.ReadFile(certFile)
	if err != nil {
		return ""
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return ""
	}
	return hubproto.Pin(c)
}

func userCmd(st *hub.Store, pos []string) {
	if len(pos) == 0 {
		fatal(errors.New("usage: kodeblue-hub user add|del|list [name]"))
	}
	switch pos[0] {
	case "list":
		for _, u := range st.Users() {
			last := "never"
			if !u.LastLogin.IsZero() {
				last = u.LastLogin.Format(time.RFC3339)
			}
			fmt.Printf("%-20s created %s  last login %s\n", u.Name, u.CreatedAt.Format("2006-01-02"), last)
		}
	case "add":
		if len(pos) < 2 {
			fatal(errors.New("usage: kodeblue-hub user add <name>  (password on stdin)"))
		}
		pw := readSecret("Password for " + pos[1] + " (min 12 chars): ")
		// On a terminal, a typo would lock the operator out: ask twice.
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			if again := readSecret("Repeat the password: "); again != pw {
				fatal(errors.New("the passwords do not match"))
			}
		}
		if err := st.AddUser(pos[1], pw); err != nil {
			fatal(err)
		}
		st.Audit("cli", "user.add", "", pos[1], "")
		fmt.Println("user", pos[1], "saved")
	case "del":
		if len(pos) < 2 {
			fatal(errors.New("usage: kodeblue-hub user del <name>"))
		}
		if err := st.DeleteUser(pos[1]); err != nil {
			fatal(err)
		}
		st.Audit("cli", "user.del", "", pos[1], "")
		fmt.Println("user", pos[1], "deleted")
	default:
		fatal(fmt.Errorf("unknown user subcommand %q", pos[0]))
	}
}

// fleetSetting is one value `kodeblue-hub fleet` manages. Secrets are never
// printed back; the inference settings are handed to servers at enrollment,
// the Slack webhook is the hub's own destination (servers never see it).
type fleetSetting struct {
	key    string
	secret bool
	check  func(string) error
}

var fleetSettings = map[string]fleetSetting{
	"telegram-bot-token": {key: "telegram_bot_token", secret: true, check: notify.ValidateTelegramToken},
	"telegram-chat-id":   {key: "telegram_chat_id", check: notify.ValidateTelegramChat},
	"inference-url":      {key: hub.SettingInferenceURL, check: checkHTTPURL},
	"inference-model":    {key: hub.SettingInferenceModel},
	"inference-provider": {key: hub.SettingInferenceProvider},
	"inference-key":      {key: hub.SettingInferenceKey, secret: true},
	"slack-webhook":      {key: "slack_webhook", secret: true, check: hub.ValidateWebhook},
}

func fleetCmd(st *hub.Store, pos []string) {
	names := make([]string, 0, len(fleetSettings))
	for name := range fleetSettings {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(pos) == 0 || pos[0] == "status" {
		// inference-* fold into the "default" connection; show the result.
		for _, c := range st.Connections() {
			fmt.Printf("connection %-8s %s %s (key %s)\n", c.ID, c.Kind, c.BaseURL, map[bool]string{true: "set", false: "not set"}[c.APIKey != ""])
		}
		if r, ok := st.FleetAgentSettings().Models["default"]; ok {
			fmt.Printf("default model       %s on %s\n", r.Model, map[bool]string{true: r.Connection, false: "each server's own endpoint"}[r.Connection != ""])
		}
		for _, name := range names {
			if strings.HasPrefix(name, "inference-") {
				continue
			}
			fs, v := fleetSettings[name], st.Setting(fleetSettings[name].key)
			switch {
			case v == "":
				v = "not set"
			case fs.secret:
				v = "set"
			}
			fmt.Printf("%-19s %s\n", name, v)
		}
		return
	}
	fs, ok := fleetSettings[""]
	if len(pos) >= 2 {
		fs, ok = fleetSettings[pos[1]]
	}
	if !ok {
		fatal(fmt.Errorf("usage: kodeblue-hub fleet set|clear|status <%s>", strings.Join(names, "|")))
	}
	switch pos[0] {
	case "set":
		v := readSecret(pos[1] + ": ")
		if v == "" {
			fatal(errors.New("empty value; use `fleet clear` to remove a setting"))
		}
		if fs.check != nil {
			if err := fs.check(v); err != nil {
				fatal(err)
			}
		}
		if err := st.SetSetting(fs.key, v); err != nil {
			fatal(err)
		}
		st.Audit("cli", "fleet.set", "", pos[1], "")
		if pos[1] == "slack-webhook" || strings.HasPrefix(pos[1], "telegram-") {
			fmt.Println(pos[1], "saved: notification destinations are configured on the hub")
		} else {
			fmt.Println(pos[1], "saved; servers that enroll from now on receive it if they have none")
		}
	case "clear":
		_ = st.SetSetting(fs.key, "")
		st.Audit("cli", "fleet.clear", "", pos[1], "")
		fmt.Println(pos[1], "cleared")
	default:
		fatal(fmt.Errorf("unknown fleet subcommand %q", pos[0]))
	}
}

func checkHTTPURL(v string) error {
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("inference-url must be an http(s) URL, e.g. https://api.example.com")
	}
	return nil
}

// readSecret reads one line from stdin, without echo when it is a terminal.
func readSecret(prompt string) string {
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(os.Stderr, prompt)
		off := exec.Command("stty", "-echo")
		off.Stdin = os.Stdin
		_ = off.Run()
		defer func() {
			on := exec.Command("stty", "echo")
			on.Stdin = os.Stdin
			_ = on.Run()
			fmt.Fprintln(os.Stderr)
		}()
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

func mustStore(dir string) *hub.Store {
	st, err := hub.OpenStore(dir)
	if err != nil {
		fatal(err)
	}
	return st
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "kodeblue-hub:", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: kodeblue-hub <command> [--data /var/lib/kodeblue-hub]
  serve [--listen :8443] (--tls-cert f --tls-key f | --self-signed | --behind-proxy) [--public-url https://…] [--dist dir]
        [--http-listen 127.0.0.1:8080]   (extra loopback console listener, e.g. for an SSH tunnel)
        [--console-allow CIDR,…]         (only these addresses see the console; servers can always sync)
        [--trusted-proxy CIDR,…]         (with --behind-proxy: proxies whose X-Forwarded-For is believed; default loopback)
        [--endpoint-allow CIDR,…]        (loopback/link-local addresses the hub may reach model endpoints at; default none)
  user add|del|list <name>          (password read from stdin)
  server add <name> --public-url …  (prints the one-time install command; serve must have run once)
  fleet set|clear|status inference-url|inference-model|inference-provider|inference-key|slack-webhook|telegram-bot-token|telegram-chat-id
                                    (value read from stdin; inference-* set the "default" model connection and default model)
  pin | version`)
}

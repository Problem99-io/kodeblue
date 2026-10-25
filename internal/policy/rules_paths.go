package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

// PathPolicy enforces file-system access boundaries.
type PathPolicy struct {
	projectRoot     string
	allowWritePaths []string
	denyPaths       []string
}

// NewPathPolicy resolves configured paths relative to the project root
// and returns a PathPolicy.
func NewPathPolicy(cfg *Config) (*PathPolicy, error) {
	root := cfg.Paths.ProjectRoot
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}

	allowWrite := make([]string, 0, len(cfg.Paths.AllowWritePaths))
	for _, p := range cfg.Paths.AllowWritePaths {
		abs := resolvePath(absRoot, p)
		allowWrite = append(allowWrite, abs)
	}

	deny := make([]string, 0, len(cfg.Paths.DenyPaths))
	for _, p := range cfg.Paths.DenyPaths {
		abs := resolvePath(absRoot, p)
		deny = append(deny, abs)
	}

	return &PathPolicy{
		projectRoot:     absRoot,
		allowWritePaths: allowWrite,
		denyPaths:       deny,
	}, nil
}

// CheckRead validates that path is within the project root and not denied.
func (p *PathPolicy) CheckRead(path string) error {
	return p.CheckReadAtRoot(p.projectRoot, path)
}

// CheckReadAtRoot resolves relative paths against the run's effective root
// instead of the daemon process working directory, then enforces both the
// run-level boundary and the configured project/deny boundaries.
func (p *PathPolicy) CheckReadAtRoot(root, path string) error {
	abs, scopeRoot, err := p.resolveAtRoot(root, path)
	if err != nil {
		return err
	}

	if !isWithin(abs, scopeRoot) {
		return fmt.Errorf("path %q is outside run root %q", abs, scopeRoot)
	}

	if reason := p.matchesDeny(abs); reason != "" {
		return fmt.Errorf("path %q is denied: %s", abs, reason)
	}

	return nil
}

// CheckWrite validates that path is within the allowed write paths,
// inside the project root, and not denied.
func (p *PathPolicy) CheckWrite(path string) error {
	return p.CheckWriteAtRoot(p.projectRoot, path)
}

// CheckWriteAtRoot is the write equivalent of CheckReadAtRoot. Configured
// write allowlists remain authoritative after the run-level boundary check.
func (p *PathPolicy) CheckWriteAtRoot(root, path string) error {
	abs, scopeRoot, err := p.resolveAtRoot(root, path)
	if err != nil {
		return err
	}

	if !isWithin(abs, scopeRoot) {
		return fmt.Errorf("path %q is outside run root %q", abs, scopeRoot)
	}

	if reason := p.matchesDeny(abs); reason != "" {
		return fmt.Errorf("path %q is denied: %s", abs, reason)
	}

	if len(p.allowWritePaths) > 0 {
		allowed := false
		for _, aw := range p.allowWritePaths {
			if isWithin(abs, aw) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("path %q is not within allowed write paths", abs)
		}
	}

	return nil
}

func (p *PathPolicy) resolveAtRoot(root, path string) (abs, scopeRoot string, err error) {
	if strings.TrimSpace(root) == "" {
		root = p.projectRoot
	}
	scopeRoot, err = filepath.Abs(root)
	if err != nil {
		return "", "", fmt.Errorf("resolve run root: %w", err)
	}
	scopeRoot = filepath.Clean(scopeRoot)
	if !isWithin(scopeRoot, p.projectRoot) {
		return "", "", fmt.Errorf("run root %q is outside project root %q", scopeRoot, p.projectRoot)
	}
	if strings.TrimSpace(path) == "" {
		abs = scopeRoot
	} else {
		abs = resolvePath(scopeRoot, path)
	}
	if !isWithin(abs, p.projectRoot) {
		return "", "", fmt.Errorf("path %q is outside project root %q", abs, p.projectRoot)
	}
	return abs, scopeRoot, nil
}

// matchesDeny returns a reason string if the path matches any deny entry.
func (p *PathPolicy) matchesDeny(abs string) string {
	for _, d := range p.denyPaths {
		if isWithin(abs, d) {
			return fmt.Sprintf("matches deny path %q", d)
		}
	}
	return ""
}

// isWithin reports whether child is inside or equal to parent.
func isWithin(child, parent string) bool {
	rel := parent + string(filepath.Separator)
	return child == parent || strings.HasPrefix(child, rel)
}

// resolvePath resolves p against root. If p is already absolute it
// is cleaned and returned as-is.
func resolvePath(root, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(root, p)
}

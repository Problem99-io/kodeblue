package skill

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Registry discovers and caches skills from the filesystem.
type Registry struct {
	mu          sync.RWMutex
	skills      map[string]*Definition // keyed by name
	projectRoot string
	permissions *Permissions
	logger      *slog.Logger
	fingerprint string // directory mtimes as of the last Discover
}

// NewRegistry creates a skill registry. Call Discover() to populate it.
func NewRegistry(projectRoot string, permissions *Permissions, logger *slog.Logger) *Registry {
	return &Registry{
		skills:      make(map[string]*Definition),
		projectRoot: projectRoot,
		permissions: permissions,
		logger:      logger,
	}
}

// searchDirs returns the skill directory: <project>/.kodeblue/skills.
func (r *Registry) searchDirs() []string {
	return []string{filepath.Join(r.projectRoot, ".kodeblue", "skills")}
}

// Discover scans the skill directory for SKILL.md files.
func (r *Registry) Discover() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.discoverLocked()
}

func (r *Registry) discoverLocked() {
	// Clear previous
	r.skills = make(map[string]*Definition)

	dirs := r.searchDirs()
	for _, dir := range dirs {
		r.scanDir(dir)
	}
	r.fingerprint = fingerprintDirs(dirs)

	r.logger.Info("skills discovered", "count", len(r.skills))
}

// Refresh re-scans only when the skill directory has changed since the last
// discovery. A skill an agent writes mid-session (a new subdirectory bumps the
// parent's mtime) is therefore visible on the next run without a restart.
func (r *Registry) Refresh() {
	r.mu.RLock()
	previous := r.fingerprint
	current := fingerprintDirs(r.searchDirs())
	r.mu.RUnlock()

	if current == previous {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check under the write lock: a concurrent Refresh may have won the race.
	if r.fingerprint == current {
		return
	}
	r.discoverLocked()
}

// fingerprintDirs summarizes the search directories by modification time.
// Adding or removing a skill subdirectory bumps its parent's mtime, so this is
// enough to detect an install without re-reading every SKILL.md.
func fingerprintDirs(dirs []string) string {
	var sb strings.Builder
	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil {
			sb.WriteString(dir)
			sb.WriteString("\x00-\x00")
			continue
		}
		sb.WriteString(dir)
		sb.WriteString("\x00")
		sb.WriteString(strconv.FormatInt(info.ModTime().UnixNano(), 10))
		sb.WriteString("\x00")
	}
	return sb.String()
}

// scanDir reads all <name>/SKILL.md entries from a directory.
func (r *Registry) scanDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // directory doesn't exist or unreadable — skip silently
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		skillFile := filepath.Join(dir, name, "SKILL.md")
		raw, err := os.ReadFile(skillFile)
		if err != nil {
			continue
		}

		def, err := ParseMarkdown(string(raw))
		if err != nil {
			r.logger.Warn("invalid SKILL.md, skipping", "path", skillFile, "error", err)
			continue
		}

		// Verify directory name matches frontmatter name
		if def.Name != name {
			r.logger.Warn("skill name mismatch, skipping",
				"directory", name, "frontmatter_name", def.Name, "path", skillFile)
			continue
		}

		def.FilePath = skillFile
		def.DirectoryPath = filepath.Join(dir, name)

		// Check permission — skip denied skills
		if r.permissions != nil {
			perm := r.permissions.Resolve(def.Name)
			if perm == PermissionDeny {
				continue
			}
		}

		r.skills[def.Name] = def
	}
}

// List returns summaries of all discovered, permitted skills.
func (r *Registry) List() []Summary {
	r.mu.RLock()
	defer r.mu.RUnlock()

	summaries := make([]Summary, 0, len(r.skills))
	for _, def := range r.skills {
		summaries = append(summaries, Summary{
			Name:        def.Name,
			Description: def.Description,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Name < summaries[j].Name
	})
	return summaries
}

// Load returns the full definition for a skill by name.
func (r *Registry) Load(name string) (*Definition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.skills[name]
	return def, ok
}

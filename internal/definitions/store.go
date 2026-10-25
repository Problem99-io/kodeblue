package definitions

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/policy"
)

type Definition struct {
	ID        string           `json:"id"`
	Title     string           `json:"title"`
	Snippet   string           `json:"snippet"`
	Content   string           `json:"content"`
	Important bool             `json:"important,omitempty"`
	Scope     []string         `json:"scope"`
	Notes     []DefinitionNote `json:"notes,omitempty"`
	Rules     []DefinitionRule `json:"rules,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

type DefinitionNote struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

type DefinitionRule struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

// staleTempAge is how old a temporary file must be before it counts as left
// behind by a crash; a live write finishes in well under a second.
const staleTempAge = time.Minute

type Store struct {
	projectRoot string
}

func NewStore(projectRoot string) *Store {
	return &Store{projectRoot: strings.TrimSpace(projectRoot)}
}

func (s *Store) Root() string {
	if s.projectRoot == "" {
		return filepath.Join(policy.ProjectDir("."), "definitions")
	}
	return filepath.Join(policy.ProjectDir(s.projectRoot), "definitions")
}

func (s *Store) List() ([]Definition, error) {
	// 0o775 (group-writable) — this dir lives in the shared workspace under the
	// worktree; the backend (a different uid in the shared group) must be able to
	// clean it up when archiving a task. 0o755 left it undeletable and broke
	// worktree removal on archive. Matches the projectmap dirs (also 0o775).
	if err := os.MkdirAll(s.Root(), 0o775); err != nil {
		return nil, fmt.Errorf("ensure definitions dir: %w", err)
	}
	s.RemoveTempFiles(staleTempAge)
	entries, err := os.ReadDir(s.Root())
	if err != nil {
		return nil, fmt.Errorf("read definitions dir: %w", err)
	}
	items := make([]Definition, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		def, err := s.Get(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			// One unreadable file (an empty one left by a crash before writes
			// were atomic, or one edited by hand) must not hide every other
			// definition from the agents' prompts. Get still reports it.
			continue
		}
		if def == nil {
			continue
		}
		items = append(items, *def)
	}
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Title) < strings.ToLower(items[j].Title)
	})
	return items, nil
}

func (s *Store) Get(id string) (*Definition, error) {
	path, err := s.pathForID(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read definition: %w", err)
	}
	var def Definition
	if err := json.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("decode definition: %w", err)
	}
	sanitizeDefinition(&def)
	return &def, nil
}

func (s *Store) Create(def Definition) (*Definition, error) {
	// 0o775 (group-writable) — this dir lives in the shared workspace under the
	// worktree; the backend (a different uid in the shared group) must be able to
	// clean it up when archiving a task. 0o755 left it undeletable and broke
	// worktree removal on archive. Matches the projectmap dirs (also 0o775).
	if err := os.MkdirAll(s.Root(), 0o775); err != nil {
		return nil, fmt.Errorf("ensure definitions dir: %w", err)
	}
	now := time.Now().UTC()
	def.ID = internal.NewID("def")
	def.CreatedAt = now
	def.UpdatedAt = now
	sanitizeDefinition(&def)
	if err := validateDefinition(def); err != nil {
		return nil, err
	}
	if err := s.write(def); err != nil {
		return nil, err
	}
	return &def, nil
}

func (s *Store) Update(def Definition) (*Definition, error) {
	if strings.TrimSpace(def.ID) == "" {
		return nil, fmt.Errorf("definition id is required")
	}
	existing, err := s.Get(def.ID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}
	def.CreatedAt = existing.CreatedAt
	def.UpdatedAt = time.Now().UTC()
	sanitizeDefinition(&def)
	if err := validateDefinition(def); err != nil {
		return nil, err
	}
	if err := s.write(def); err != nil {
		return nil, err
	}
	return &def, nil
}

func (s *Store) Delete(id string) (bool, error) {
	path, err := s.pathForID(id)
	if err != nil {
		return false, err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("delete definition: %w", err)
	}
	return true, nil
}

func (s *Store) pathForID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("definition id is required")
	}
	if strings.Contains(id, string(filepath.Separator)) || strings.Contains(id, "..") {
		return "", fmt.Errorf("invalid definition id")
	}
	return filepath.Join(s.Root(), id+".json"), nil
}

func (s *Store) write(def Definition) error {
	path, err := s.pathForID(def.ID)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(def, "", "  ")
	if err != nil {
		return fmt.Errorf("encode definition: %w", err)
	}
	data = append(data, '\n')
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("write definition: %w", err)
	}
	return nil
}

// writeFileAtomic replaces path with data so that a crash at any moment
// leaves either the old definition or the new one, never an empty or partial
// file: the data goes to a temporary file in the same directory, which is
// fsynced, closed and renamed over path, and the directory is fsynced so the
// rename is durable too. A new file gets perm less the umask, as
// os.WriteFile would; a replaced one keeps its mode.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir, base := filepath.Split(path)
	var tmp *os.File
	for range 10 {
		var b [8]byte
		if _, err = rand.Read(b[:]); err != nil {
			return err
		}
		tmp, err = os.OpenFile(filepath.Join(dir, "."+base+".tmp-"+hex.EncodeToString(b[:])), os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if !os.IsExist(err) {
			break
		}
	}
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() {
		if err = tmp.Chmod(info.Mode().Perm()); err != nil {
			tmp.Close()
			return err
		}
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err = d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// tempFilePattern matches the names writeFileAtomic gives its files. They
// start with a dot and do not end in .json, so List never reads one.
var tempFilePattern = regexp.MustCompile(`^\..+\.json\.tmp-[0-9a-f]{16}$`)

// IsTempFile reports whether name is one of the store's temporary files.
func IsTempFile(name string) bool { return tempFilePattern.MatchString(name) }

// RemoveTempFiles deletes temporary files at least olderThan old: ones that
// writes interrupted by a crash left behind. List passes staleTempAge, so a
// write in flight keeps its file.
func (s *Store) RemoveTempFiles(olderThan time.Duration) {
	entries, err := os.ReadDir(s.Root())
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !IsTempFile(entry.Name()) {
			continue
		}
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() && time.Since(info.ModTime()) >= olderThan {
			_ = os.Remove(filepath.Join(s.Root(), entry.Name()))
		}
	}
}

func validateDefinition(def Definition) error {
	if strings.TrimSpace(def.Title) == "" {
		return fmt.Errorf("title is required")
	}
	if strings.TrimSpace(def.Snippet) == "" {
		return fmt.Errorf("snippet is required")
	}
	if strings.TrimSpace(def.Content) == "" {
		return fmt.Errorf("content is required")
	}
	if len(def.Scope) == 0 {
		return fmt.Errorf("scope must include at least one file or path")
	}
	for _, path := range def.Scope {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("scope entries must not be empty")
		}
	}
	for _, note := range def.Notes {
		if strings.TrimSpace(note.ID) == "" {
			return fmt.Errorf("each note requires an id")
		}
		if strings.TrimSpace(note.Title) == "" {
			return fmt.Errorf("each note requires a title")
		}
		if strings.TrimSpace(note.Content) == "" {
			return fmt.Errorf("each note requires content")
		}
	}
	for _, rule := range def.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("each rule requires an id")
		}
		if strings.TrimSpace(rule.Title) == "" {
			return fmt.Errorf("each rule requires a title")
		}
		if strings.TrimSpace(rule.Content) == "" {
			return fmt.Errorf("each rule requires content")
		}
	}
	return nil
}

func sanitizeDefinition(def *Definition) {
	def.ID = strings.TrimSpace(def.ID)
	def.Title = strings.TrimSpace(def.Title)
	def.Snippet = strings.TrimSpace(def.Snippet)
	def.Content = strings.TrimSpace(def.Content)
	def.Scope = sanitizeUniqueStrings(def.Scope)
	def.Notes = sanitizeNotes(def.Notes)
	def.Rules = sanitizeRules(def.Rules)
}

func sanitizeNotes(notes []DefinitionNote) []DefinitionNote {
	if len(notes) == 0 {
		return nil
	}
	cleaned := make([]DefinitionNote, 0, len(notes))
	seen := map[string]struct{}{}
	for _, note := range notes {
		note.ID = sanitizeItemID(note.ID, "note")
		note.Title = strings.TrimSpace(note.Title)
		note.Content = strings.TrimSpace(note.Content)
		if note.ID == "" || note.Title == "" || note.Content == "" {
			continue
		}
		if _, ok := seen[note.ID]; ok {
			continue
		}
		seen[note.ID] = struct{}{}
		cleaned = append(cleaned, note)
	}
	return cleaned
}

func sanitizeRules(rules []DefinitionRule) []DefinitionRule {
	if len(rules) == 0 {
		return nil
	}
	cleaned := make([]DefinitionRule, 0, len(rules))
	seen := map[string]struct{}{}
	for _, rule := range rules {
		rule.ID = sanitizeItemID(rule.ID, "rule")
		rule.Title = strings.TrimSpace(rule.Title)
		rule.Content = strings.TrimSpace(rule.Content)
		if rule.ID == "" || rule.Title == "" || rule.Content == "" {
			continue
		}
		if _, ok := seen[rule.ID]; ok {
			continue
		}
		seen[rule.ID] = struct{}{}
		cleaned = append(cleaned, rule)
	}
	return cleaned
}

func sanitizeUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cleaned := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = filepath.ToSlash(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	return cleaned
}

func sanitizeItemID(value string, prefix string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return internal.NewID(prefix)
	}
	value = strings.ReplaceAll(value, string(filepath.Separator), "-")
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, "..", "-")
	if value == "" {
		return internal.NewID(prefix)
	}
	return value
}

func SortDefinitionItems(def *Definition) {
	if def == nil {
		return
	}
	sort.Slice(def.Notes, func(i, j int) bool {
		return def.Notes[i].ID < def.Notes[j].ID
	})
	sort.Slice(def.Rules, func(i, j int) bool {
		return def.Rules[i].ID < def.Rules[j].ID
	})
}

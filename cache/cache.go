// Package cache provides a content-addressed build cache for pipeline artifacts.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const formatVersion = "v1"

// Store is a content-addressed cache backed by a directory on disk.
type Store struct {
	dir string
}

// DefaultDir returns the default cache directory, respecting $XDG_CACHE_HOME.
func DefaultDir() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = os.TempDir()
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "tinybpf", formatVersion)
}

// Open creates a Store at DefaultDir, creating the directory if needed.
func Open() (*Store, error) {
	return NewStore(DefaultDir())
}

// NewStore creates a Store at the given directory, creating it if needed.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("cache: create directory: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the root directory of the cache store.
func (s *Store) Dir() string {
	return s.dir
}

// Lookup returns the path to a cached artifact and true if the key exists.
func (s *Store) Lookup(key string) (string, bool) {
	p := s.path(key)
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return p, true
}

// Put copies the file at srcPath into the cache under the given key.
func (s *Store) Put(key, srcPath string) error {
	dst := s.path(key)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("cache: create shard dir: %w", err)
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("cache: read source: %w", err)
	}
	return atomicWrite(dst, data)
}

// atomicWrite writes data to dst via a temp file and rename so that readers
// never see a partially-written artifact.
func atomicWrite(dst string, data []byte) (retErr error) {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return fmt.Errorf("cache: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if retErr != nil {
			cleanupTempFile(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("cache: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cache: close: %w", err)
	}
	return os.Rename(tmpPath, dst) //nolint:gosec // tmpPath is from os.CreateTemp, not user input
}

// cleanupTempFile removes a temp file on a best-effort basis.
func cleanupTempFile(path string) {
	_ = os.Remove(path)
}

// Key computes a SHA-256 cache key from the concatenation of all parts.
func Key(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HashFile returns the hex-encoded SHA-256 digest of a file's contents.
func HashFile(path string) (hash string, retErr error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if cErr := f.Close(); retErr == nil {
			retErr = cErr
		}
	}()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashFiles returns a combined hash of multiple files in the order given.
func HashFiles(paths []string) (string, error) {
	h := sha256.New()
	for _, p := range paths {
		if err := hashFileInto(h, p); err != nil {
			return "", err
		}
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashFileInto hashes the contents of a file into a SHA-256 hash.
func hashFileInto(h io.Writer, path string) (retErr error) {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if cErr := f.Close(); retErr == nil {
			retErr = cErr
		}
	}()
	_, err = io.Copy(h, f)
	return err
}

// Clean removes all cached artifacts.
func (s *Store) Clean() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(s.dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// path returns the on-disk path for a cache key, using the first two hex
// characters as a shard directory.
func (s *Store) path(key string) string {
	shard := key[:2]
	return filepath.Join(s.dir, shard, key)
}

// SortedSections returns a deterministic string representation of a
// section map for use in cache keys.
func SortedSections(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
	}
	return b.String()
}

// sortStrings sorts a slice of strings in place (insertion sort to avoid
// importing sort for a small utility).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

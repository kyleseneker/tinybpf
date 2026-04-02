package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultDir(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T)
		contain string
	}{
		{
			name: "respects XDG_CACHE_HOME",
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("XDG_CACHE_HOME", "/tmp/xdg-test")
			},
			contain: filepath.Join("/tmp/xdg-test", "tinybpf", formatVersion),
		},
		{
			name: "falls back to home/.cache",
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("XDG_CACHE_HOME", "")
			},
			contain: filepath.Join(".cache", "tinybpf", formatVersion),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)
			got := DefaultDir()
			if !strings.Contains(got, tt.contain) {
				t.Errorf("DefaultDir() = %q, want to contain %q", got, tt.contain)
			}
		})
	}
}

func TestNewStore(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{
			name: "creates directory",
			dir:  filepath.Join(t.TempDir(), "new-cache"),
		},
		{
			name: "existing directory is fine",
			dir:  t.TempDir(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewStore(tt.dir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if s.Dir() != tt.dir {
				t.Errorf("Dir() = %q, want %q", s.Dir(), tt.dir)
			}
			info, err := os.Stat(tt.dir)
			if err != nil {
				t.Fatalf("directory not created: %v", err)
			}
			if !info.IsDir() {
				t.Error("expected directory")
			}
		})
	}
}

func TestLookup(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		setup   func(t *testing.T)
		key     string
		wantHit bool
	}{
		{
			name:    "miss on empty cache",
			key:     "ab" + strings.Repeat("0", 62),
			wantHit: false,
		},
		{
			name: "hit after put",
			key:  "cd" + strings.Repeat("1", 62),
			setup: func(t *testing.T) {
				t.Helper()
				src := filepath.Join(t.TempDir(), "src")
				os.WriteFile(src, []byte("data"), 0o600)
				if err := s.Put("cd"+strings.Repeat("1", 62), src); err != nil {
					t.Fatal(err)
				}
			},
			wantHit: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}
			path, hit := s.Lookup(tt.key)
			if hit != tt.wantHit {
				t.Errorf("hit = %v, want %v", hit, tt.wantHit)
			}
			if tt.wantHit && path == "" {
				t.Error("expected non-empty path on hit")
			}
			if !tt.wantHit && path != "" {
				t.Error("expected empty path on miss")
			}
		})
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPut(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, s *Store, key string) string
		wantErr bool
		check   func(t *testing.T, s *Store, key string)
	}{
		{
			name: "stores and retrieves artifact",
			setup: func(t *testing.T, _ *Store, _ string) string {
				t.Helper()
				return writeTempFile(t, "hello cache")
			},
			check: func(t *testing.T, s *Store, key string) {
				t.Helper()
				path, hit := s.Lookup(key)
				if !hit {
					t.Fatal("expected cache hit")
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != "hello cache" {
					t.Errorf("cached content = %q, want %q", data, "hello cache")
				}
				shard := filepath.Join(s.Dir(), key[:2])
				if _, err := os.Stat(shard); err != nil {
					t.Errorf("shard directory not created: %v", err)
				}
			},
		},
		{
			name: "overwrite replaces content",
			setup: func(t *testing.T, s *Store, key string) string {
				t.Helper()
				src := writeTempFile(t, "version1")
				if err := s.Put(key, src); err != nil {
					t.Fatal(err)
				}
				return writeTempFile(t, "version2")
			},
			check: func(t *testing.T, s *Store, key string) {
				t.Helper()
				path, hit := s.Lookup(key)
				if !hit {
					t.Fatal("expected hit")
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != "version2" {
					t.Errorf("got %q, want %q", data, "version2")
				}
			},
		},
		{
			name: "missing source returns error",
			setup: func(t *testing.T, _ *Store, _ string) string {
				t.Helper()
				return "/nonexistent/file"
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			key := "ab" + strings.Repeat("0", 62)
			srcPath := tt.setup(t, s, key)
			err = s.Put(key, srcPath)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.check(t, s, key)
		})
	}
}

func TestKey(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
		check func(t *testing.T, key string)
	}{
		{
			name:  "single part produces 64 hex chars",
			parts: []string{"hello"},
			check: func(t *testing.T, key string) {
				t.Helper()
				if len(key) != 64 {
					t.Errorf("key length = %d, want 64", len(key))
				}
			},
		},
		{
			name:  "multiple parts",
			parts: []string{"a", "b", "c"},
			check: func(t *testing.T, key string) {
				t.Helper()
				if len(key) != 64 {
					t.Errorf("key length = %d, want 64", len(key))
				}
			},
		},
		{
			name:  "deterministic",
			parts: []string{"hello", "world"},
			check: func(t *testing.T, key string) {
				t.Helper()
				if key != Key("hello", "world") {
					t.Error("same inputs produced different keys")
				}
			},
		},
		{
			name:  "separator prevents collisions",
			parts: []string{"ab"},
			check: func(t *testing.T, key string) {
				t.Helper()
				if key == Key("a", "b") {
					t.Error("Key(\"ab\") should differ from Key(\"a\", \"b\")")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, Key(tt.parts...))
		})
	}
}

func TestHashFile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
		check   func(t *testing.T, hash, path string)
	}{
		{
			name: "produces 64-char hex digest",
			setup: func(t *testing.T) string {
				t.Helper()
				f := filepath.Join(t.TempDir(), "test")
				os.WriteFile(f, []byte("content"), 0o600)
				return f
			},
			check: func(t *testing.T, hash, _ string) {
				t.Helper()
				if len(hash) != 64 {
					t.Errorf("hash length = %d, want 64", len(hash))
				}
			},
		},
		{
			name: "deterministic across calls",
			setup: func(t *testing.T) string {
				t.Helper()
				f := filepath.Join(t.TempDir(), "test")
				os.WriteFile(f, []byte("content"), 0o600)
				return f
			},
			check: func(t *testing.T, hash, path string) {
				t.Helper()
				h2, err := HashFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if hash != h2 {
					t.Error("same file should produce same hash")
				}
			},
		},
		{
			name: "missing file returns error",
			setup: func(t *testing.T) string {
				t.Helper()
				return "/nonexistent/file"
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			hash, err := HashFile(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, hash, path)
			}
		})
	}
}

func TestHashFiles(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) []string
		wantErr bool
		check   func(t *testing.T, hash string, paths []string)
	}{
		{
			name: "produces 64-char hex digest",
			setup: func(t *testing.T) []string {
				t.Helper()
				dir := t.TempDir()
				f1 := filepath.Join(dir, "a")
				f2 := filepath.Join(dir, "b")
				os.WriteFile(f1, []byte("aaa"), 0o600)
				os.WriteFile(f2, []byte("bbb"), 0o600)
				return []string{f1, f2}
			},
			check: func(t *testing.T, hash string, _ []string) {
				t.Helper()
				if len(hash) != 64 {
					t.Errorf("hash length = %d, want 64", len(hash))
				}
			},
		},
		{
			name: "differs from single-file hash",
			setup: func(t *testing.T) []string {
				t.Helper()
				dir := t.TempDir()
				f1 := filepath.Join(dir, "a")
				f2 := filepath.Join(dir, "b")
				os.WriteFile(f1, []byte("aaa"), 0o600)
				os.WriteFile(f2, []byte("bbb"), 0o600)
				return []string{f1, f2}
			},
			check: func(t *testing.T, hash string, paths []string) {
				t.Helper()
				hSingle, err := HashFile(paths[0])
				if err != nil {
					t.Fatal(err)
				}
				if hash == hSingle {
					t.Error("multi-file hash should differ from single-file hash")
				}
			},
		},
		{
			name: "missing file returns error",
			setup: func(t *testing.T) []string {
				t.Helper()
				return []string{"/nonexistent"}
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := tt.setup(t)
			hash, err := HashFiles(paths)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, hash, paths)
			}
		})
	}
}

func TestClean(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, s *Store)
		check func(t *testing.T, s *Store)
	}{
		{
			name: "removes cached entries",
			setup: func(t *testing.T, s *Store) {
				t.Helper()
				src := filepath.Join(t.TempDir(), "f")
				os.WriteFile(src, []byte("data"), 0o600)
				if err := s.Put("ab"+strings.Repeat("5", 62), src); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, s *Store) {
				t.Helper()
				entries, _ := os.ReadDir(s.Dir())
				if len(entries) != 0 {
					t.Errorf("expected empty directory, got %d entries", len(entries))
				}
			},
		},
		{
			name:  "no-op on empty directory",
			setup: func(t *testing.T, s *Store) { t.Helper() },
			check: func(t *testing.T, s *Store) { t.Helper() },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			tt.setup(t, s)
			if err := s.Clean(); err != nil {
				t.Fatalf("Clean() error: %v", err)
			}
			tt.check(t, s)
		})
	}
}

func TestEvict(t *testing.T) {
	tests := []struct {
		name       string
		maxAge     time.Duration
		setup      func(t *testing.T, s *Store)
		wantRemove int
	}{
		{
			name:   "removes old entries",
			maxAge: time.Millisecond,
			setup: func(t *testing.T, s *Store) {
				t.Helper()
				src := filepath.Join(t.TempDir(), "f")
				os.WriteFile(src, []byte("data"), 0o600)
				key := "ab" + strings.Repeat("0", 62)
				if err := s.Put(key, src); err != nil {
					t.Fatal(err)
				}
				// Backdate the file so it appears old.
				p := s.path(key)
				old := time.Now().Add(-48 * time.Hour)
				os.Chtimes(p, old, old)
			},
			wantRemove: 1,
		},
		{
			name:   "keeps recent entries",
			maxAge: time.Hour,
			setup: func(t *testing.T, s *Store) {
				t.Helper()
				src := filepath.Join(t.TempDir(), "f")
				os.WriteFile(src, []byte("data"), 0o600)
				if err := s.Put("cd"+strings.Repeat("1", 62), src); err != nil {
					t.Fatal(err)
				}
			},
			wantRemove: 0,
		},
		{
			name:       "no-op on empty cache",
			maxAge:     time.Millisecond,
			setup:      func(t *testing.T, s *Store) { t.Helper() },
			wantRemove: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			tt.setup(t, s)
			n, err := s.Evict(tt.maxAge)
			if err != nil {
				t.Fatalf("Evict() error: %v", err)
			}
			if n != tt.wantRemove {
				t.Errorf("Evict() removed %d, want %d", n, tt.wantRemove)
			}
		})
	}
}

func TestSortedSections(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]string
		want string
	}{
		{"nil map", nil, ""},
		{"empty map", map[string]string{}, ""},
		{"single entry", map[string]string{"a": "1"}, "a=1"},
		{
			name: "deterministic order",
			m:    map[string]string{"b": "2", "a": "1"},
			want: "a=1,b=2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SortedSections(tt.m)
			if got != tt.want {
				t.Errorf("SortedSections() = %q, want %q", got, tt.want)
			}
		})
	}
}

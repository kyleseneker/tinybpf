package pipeline

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/kyleseneker/tinybpf/internal/diag"
	"github.com/kyleseneker/tinybpf/internal/llvm"
)

// normalizeInputs resolves all input files to LLVM IR/bitcode suitable for
// llvm-link. Archive and object inputs are expanded/extracted as needed.
func normalizeInputs(ctx context.Context, cfg Config, tools llvm.Tools, workDir string) ([]string, error) {
	if cfg.Jobs > 1 && len(cfg.Inputs) > 1 {
		return normalizeInputsParallel(ctx, cfg, tools, workDir)
	}
	return normalizeInputsSeq(ctx, cfg, tools, workDir)
}

// normalizeInputsSeq is the sequential (default) normalization path.
func normalizeInputsSeq(ctx context.Context, cfg Config, tools llvm.Tools, workDir string) ([]string, error) {
	var normalized []string
	for i, input := range cfg.Inputs {
		paths, err := normalizeSingle(ctx, cfg, tools, workDir, input, i)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, paths...)
	}
	return requireModules(normalized)
}

// normalizeInputsParallel processes inputs concurrently, bounded by cfg.Jobs.
func normalizeInputsParallel(ctx context.Context, cfg Config, tools llvm.Tools, workDir string) ([]string, error) {
	type indexedResult struct {
		index int
		paths []string
		err   error
	}

	sem := make(chan struct{}, cfg.Jobs)
	results := make(chan indexedResult, len(cfg.Inputs))
	var wg sync.WaitGroup

	for i, input := range cfg.Inputs {
		wg.Add(1)
		go func(idx int, inp string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			paths, err := normalizeSingle(ctx, cfg, tools, workDir, inp, idx)
			results <- indexedResult{index: idx, paths: paths, err: err}
		}(i, input)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	ordered := make([][]string, len(cfg.Inputs))
	var errs []error
	for r := range results {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		ordered[r.index] = r.paths
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	var normalized []string
	for _, paths := range ordered {
		normalized = append(normalized, paths...)
	}
	return requireModules(normalized)
}

// requireModules returns an error if no LLVM modules were produced.
func requireModules(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, &diag.Error{Stage: diag.StageInput,
			Err:  fmt.Errorf("no usable modules after normalization"),
			Hint: "verify provided inputs contain LLVM IR/bitcode"}
	}
	return paths, nil
}

// normalizeSingle processes a single input file, returning its normalized
// path(s).
func normalizeSingle(ctx context.Context, cfg Config, tools llvm.Tools, workDir, input string, index int) ([]string, error) {
	ext := strings.ToLower(filepath.Ext(input))
	switch ext {
	case ".ll", ".bc":
		return []string{input}, nil
	case ".o":
		bcPath := filepath.Join(workDir, fmt.Sprintf("%d_%s.llvmbc.bc", index, filepath.Base(input)))
		if err := extractBitcodeFromObject(ctx, cfg, tools, input, bcPath); err != nil {
			return nil, err
		}
		return []string{bcPath}, nil
	case ".a":
		members, err := expandArchive(ctx, cfg, tools, input, workDir)
		if err != nil {
			return nil, err
		}
		return members, nil
	}
	return nil, nil
}

// expandArchive uses llvm-ar to list and extract members from an archive,
// then recursively normalizes each member.
func expandArchive(ctx context.Context, cfg Config, tools llvm.Tools, archivePath, workDir string) ([]string, error) {
	if tools.LLVMAr == "" {
		return nil, &diag.Error{Stage: diag.StageInput,
			Err:  fmt.Errorf("archive input %q requires llvm-ar", archivePath),
			Hint: "install llvm-ar or pass --llvm-ar"}
	}

	listRes, err := llvm.Run(ctx, cfg.Timeout, tools.LLVMAr, "t", archivePath)
	if err != nil {
		return nil, &diag.Error{Stage: diag.StageInput, Err: err,
			Command: listRes.Command, Stderr: listRes.Stderr,
			Hint: "failed to list archive members"}
	}

	var out []string
	for i, line := range strings.Split(strings.TrimSpace(listRes.Stdout), "\n") {
		member := strings.TrimSpace(line)
		if member == "" {
			continue
		}

		printRes, printErr := llvm.Run(ctx, cfg.Timeout, tools.LLVMAr, "p", archivePath, member)
		if printErr != nil {
			return nil, &diag.Error{Stage: diag.StageInput, Err: printErr,
				Command: printRes.Command, Stderr: printRes.Stderr,
				Hint: "failed to read archive member"}
		}

		memberPath := filepath.Join(workDir,
			fmt.Sprintf("%s_member_%d_%s", filepath.Base(archivePath), i, sanitizeName(member)))
		if err := os.WriteFile(memberPath, []byte(printRes.Stdout), 0o600); err != nil {
			return nil, &diag.Error{Stage: diag.StageInput, Err: err,
				Hint: "failed to materialize archive member"}
		}

		ext := strings.ToLower(filepath.Ext(memberPath))
		switch ext {
		case ".ll", ".bc":
			out = append(out, memberPath)
		case ".o":
			bcPath := memberPath + ".llvmbc.bc"
			if err := extractBitcodeFromObject(ctx, cfg, tools, memberPath, bcPath); err != nil {
				return nil, err
			}
			out = append(out, bcPath)
		}
	}

	if len(out) == 0 {
		return nil, &diag.Error{Stage: diag.StageInput,
			Err:  fmt.Errorf("archive %q contained no LLVM module members", archivePath),
			Hint: "expected .ll/.bc files or .o with embedded .llvmbc section"}
	}
	return out, nil
}

// extractBitcodeFromObject uses llvm-objcopy to dump the .llvmbc section
// from an object file into a standalone bitcode file.
func extractBitcodeFromObject(ctx context.Context, cfg Config, tools llvm.Tools, objectPath, outPath string) error {
	if tools.Objcopy == "" {
		return &diag.Error{Stage: diag.StageInput,
			Err:  fmt.Errorf("object input %q requires llvm-objcopy", objectPath),
			Hint: "install llvm-objcopy or pass --llvm-objcopy"}
	}

	args := []string{
		"--dump-section=.llvmbc=" + outPath,
		objectPath,
	}
	res, err := llvm.Run(ctx, cfg.Timeout, tools.Objcopy, args...)
	if err != nil {
		return &diag.Error{Stage: diag.StageInput, Err: err,
			Command: res.Command, Stderr: res.Stderr,
			Hint: "object must include .llvmbc section for extraction"}
	}

	info, statErr := os.Stat(outPath)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return &diag.Error{Stage: diag.StageInput,
				Err:     fmt.Errorf("no .llvmbc section found in %q", objectPath),
				Command: res.Command, Stderr: res.Stderr,
				Hint: "object likely does not contain embedded bitcode"}
		}
		return &diag.Error{Stage: diag.StageInput, Err: statErr,
			Command: res.Command, Stderr: res.Stderr,
			Hint: "failed to verify extracted bitcode"}
	}
	if info.Size() == 0 {
		return &diag.Error{Stage: diag.StageInput,
			Err:     fmt.Errorf("empty .llvmbc section in %q", objectPath),
			Command: res.Command, Stderr: res.Stderr,
			Hint: ".llvmbc section was empty"}
	}
	return nil
}

var nameReplacer = strings.NewReplacer("/", "_", "\\", "_", " ", "_")

// sanitizeName replaces path separators and spaces with underscores.
func sanitizeName(s string) string {
	return nameReplacer.Replace(s)
}

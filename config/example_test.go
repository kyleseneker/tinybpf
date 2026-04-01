package config_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kyleseneker/tinybpf/config"
)

func ExampleLoad() {
	cfg, err := config.Load("tinybpf.json")
	if err != nil {
		fmt.Println("load failed:", err)
		return
	}
	fmt.Println("output:", cfg.Build.Output)
}

func ExampleFind() {
	path, err := config.Find(".")
	if err != nil {
		fmt.Println("find failed:", err)
		return
	}
	if path == "" {
		fmt.Println("no tinybpf.json found")
		return
	}
	fmt.Println("found:", path)
}

func ExampleToRequest() {
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		return
	}
	defer os.RemoveAll(dir)

	cfgData := []byte(`{"build":{"output":"build/probe.bpf.o","programs":{"handler":"kprobe/do_sys_openat2"}}}`)
	cfgPath := filepath.Join(dir, "tinybpf.json")
	os.WriteFile(cfgPath, cfgData, 0o644)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return
	}

	req := config.ToRequest(cfg)
	fmt.Println("output:", req.Output)
	fmt.Println("programs:", req.Programs)

	data, _ := json.Marshal(req.Sections)
	fmt.Println("sections:", string(data))
	// Output:
	// output: build/probe.bpf.o
	// programs: [handler]
	// sections: {"handler":"kprobe/do_sys_openat2"}
}

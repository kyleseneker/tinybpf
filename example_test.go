package tinybpf_test

import (
	"context"
	"fmt"

	"github.com/kyleseneker/tinybpf"
)

func ExampleBuild() {
	result, err := tinybpf.Build(context.Background(), tinybpf.Request{
		Package: "./bpf",
		Output:  "probe.bpf.o",
	})
	if err != nil {
		fmt.Println("build failed:", err)
		return
	}
	fmt.Println("wrote", result.Output)
}

func ExampleBuild_inputs() {
	result, err := tinybpf.Build(context.Background(), tinybpf.Request{
		Inputs:    []string{"module_a.ll", "module_b.ll"},
		Output:    "combined.bpf.o",
		EnableBTF: true,
	})
	if err != nil {
		fmt.Println("build failed:", err)
		return
	}
	fmt.Println("wrote", result.Output)
}

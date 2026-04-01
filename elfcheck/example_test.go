package elfcheck_test

import (
	"fmt"

	"github.com/kyleseneker/tinybpf/elfcheck"
)

func ExampleValidate() {
	err := elfcheck.Validate("probe.bpf.o")
	if err != nil {
		fmt.Println("invalid:", err)
		return
	}
	fmt.Println("valid BPF ELF object")
}

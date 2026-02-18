package transform

import (
	"strings"
	"testing"
)

func TestAddLicense(t *testing.T) {
	t.Run("already present", func(t *testing.T) {
		input := []string{
			`@_license = global [4 x i8] c"GPL\00", section "license", align 1`,
			"define i32 @my_func() { ret i32 0 }",
		}
		got := addLicense(input)
		count := 0
		for _, line := range got {
			if strings.Contains(line, `section "license"`) {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("expected 1 license line, got %d", count)
		}
	})

	t.Run("no define block", func(t *testing.T) {
		input := []string{`target triple = "bpf"`, `@x = global i32 0`}
		text := strings.Join(addLicense(input), "\n")
		if !strings.Contains(text, `section "license"`) {
			t.Error("license not added when no define present")
		}
	})
}

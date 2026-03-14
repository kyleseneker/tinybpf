package tinybpf_test

import (
	"context"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf"
)

func TestBuildValidation(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		req  tinybpf.Request
		want string
	}{
		{
			name: "neither Package nor Inputs",
			req:  tinybpf.Request{},
			want: "exactly one of Package or Inputs",
		},
		{
			name: "both Package and Inputs",
			req: tinybpf.Request{
				Package: "./bpf",
				Inputs:  []string{"a.ll"},
			},
			want: "exactly one of Package or Inputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tinybpf.Build(ctx, tt.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q should contain %q", err.Error(), tt.want)
			}
		})
	}
}

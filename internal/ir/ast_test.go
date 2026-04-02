package ir

import (
	"strings"
	"testing"
)

func TestEnsureBlocks(t *testing.T) {
	tests := []struct {
		name           string
		fn             *Function
		wantNumBlocks  int
		wantLabels     []string
		wantInstCounts []int // number of instructions per block
		wantKinds      [][]InstKind
	}{
		{
			name: "no-op when Blocks already populated",
			fn: &Function{
				Blocks: []*BasicBlock{
					{Label: "entry"},
				},
				BodyRaw: []string{
					"other:",
					"  ret void",
				},
			},
			wantNumBlocks:  1,
			wantLabels:     []string{"entry"},
			wantInstCounts: []int{0},
		},
		{
			name:          "no-op when BodyRaw is empty",
			fn:            &Function{},
			wantNumBlocks: 0,
		},
		{
			name: "parse labels into BasicBlock.Label",
			fn: &Function{
				BodyRaw: []string{
					"entry:",
					"  ret void",
					"exit:",
					"  unreachable",
				},
			},
			wantNumBlocks:  2,
			wantLabels:     []string{"entry", "exit"},
			wantInstCounts: []int{1, 1},
		},
		{
			name: "parse call instruction into InstCall",
			fn: &Function{
				BodyRaw: []string{
					"entry:",
					"  call void @foo(i32 %0)",
				},
			},
			wantNumBlocks:  1,
			wantLabels:     []string{"entry"},
			wantInstCounts: []int{1},
			wantKinds:      [][]InstKind{{InstCall}},
		},
		{
			name: "parse getelementptr into InstGEP",
			fn: &Function{
				BodyRaw: []string{
					"entry:",
					"  %1 = getelementptr inbounds %struct.task, ptr %0, i32 0, i32 1",
				},
			},
			wantNumBlocks:  1,
			wantLabels:     []string{"entry"},
			wantInstCounts: []int{1},
			wantKinds:      [][]InstKind{{InstGEP}},
		},
		{
			name: "parse alloca into InstAlloca",
			fn: &Function{
				BodyRaw: []string{
					"entry:",
					"  %0 = alloca i32, align 4",
				},
			},
			wantNumBlocks:  1,
			wantLabels:     []string{"entry"},
			wantInstCounts: []int{1},
			wantKinds:      [][]InstKind{{InstAlloca}},
		},
		{
			name: "other instructions as InstOther",
			fn: &Function{
				BodyRaw: []string{
					"entry:",
					"  store i32 0, ptr %0",
					"  %1 = load i32, ptr %0",
					"  ret i32 %1",
				},
			},
			wantNumBlocks:  1,
			wantLabels:     []string{"entry"},
			wantInstCounts: []int{3},
			wantKinds:      [][]InstKind{{InstOther, InstOther, InstOther}},
		},
		{
			name: "comments and blank lines within blocks as InstOther",
			fn: &Function{
				BodyRaw: []string{
					"entry:",
					"  ; this is a comment",
					"",
					"  store i32 0, ptr %0",
				},
			},
			wantNumBlocks:  1,
			wantLabels:     []string{"entry"},
			wantInstCounts: []int{3},
			wantKinds:      [][]InstKind{{InstOther, InstOther, InstOther}},
		},
		{
			name: "closing brace not added as instruction",
			fn: &Function{
				BodyRaw: []string{
					"entry:",
					"  ret void",
					"}",
				},
			},
			wantNumBlocks:  1,
			wantLabels:     []string{"entry"},
			wantInstCounts: []int{1},
			wantKinds:      [][]InstKind{{InstOther}},
		},
		{
			name: "instructions before any label create unnamed block",
			fn: &Function{
				BodyRaw: []string{
					"  ret void",
				},
			},
			wantNumBlocks:  1,
			wantLabels:     []string{""},
			wantInstCounts: []int{1},
		},
		{
			name: "mixed instruction kinds across blocks",
			fn: &Function{
				BodyRaw: []string{
					"entry:",
					"  %0 = alloca [16 x i8], align 4",
					"  %1 = getelementptr inbounds i8, ptr %0, i32 0",
					"  call void @llvm.memset.p0.i64(ptr %1, i8 0, i64 16, i1 false)",
					"  ; done with init",
					"  br label %exit",
					"exit:",
					"  ret void",
					"}",
				},
			},
			wantNumBlocks:  2,
			wantLabels:     []string{"entry", "exit"},
			wantInstCounts: []int{5, 1},
			wantKinds: [][]InstKind{
				{InstAlloca, InstGEP, InstCall, InstOther, InstOther},
				{InstOther},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			EnsureBlocks(tt.fn)

			if got := len(tt.fn.Blocks); got != tt.wantNumBlocks {
				t.Fatalf("EnsureBlocks() produced %d blocks, want %d", got, tt.wantNumBlocks)
			}

			for i, block := range tt.fn.Blocks {
				if i < len(tt.wantLabels) {
					if block.Label != tt.wantLabels[i] {
						t.Errorf("block[%d].Label = %q, want %q", i, block.Label, tt.wantLabels[i])
					}
				}
				if i < len(tt.wantInstCounts) {
					if len(block.Instructions) != tt.wantInstCounts[i] {
						var rawLines []string
						for _, inst := range block.Instructions {
							rawLines = append(rawLines, inst.Raw)
						}
						t.Errorf("block[%d] has %d instructions, want %d; instructions:\n%s",
							i, len(block.Instructions), tt.wantInstCounts[i],
							strings.Join(rawLines, "\n"))
					}
				}
				if tt.wantKinds != nil && i < len(tt.wantKinds) {
					for j, inst := range block.Instructions {
						if j < len(tt.wantKinds[i]) {
							if inst.Kind != tt.wantKinds[i][j] {
								t.Errorf("block[%d].Instructions[%d].Kind = %d, want %d (raw: %q)",
									i, j, inst.Kind, tt.wantKinds[i][j], inst.Raw)
							}
						}
					}
				}
			}
		})
	}
}

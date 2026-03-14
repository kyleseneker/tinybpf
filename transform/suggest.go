package transform

// levenshtein returns the edit distance between a and b.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	prev := make([]int, lb+1)
	for j := range prev {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		cur := make([]int, lb+1)
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(cur[j-1]+1, min(prev[j]+1, prev[j-1]+cost))
		}
		prev = cur
	}
	return prev[lb]
}

const maxSuggestDistance = 3

// closestHelper returns the known helper name closest to name, or "" if no
// match is within maxSuggestDistance edits.
func closestHelper(name string) string {
	best, bestDist := "", maxSuggestDistance+1
	for known := range helperIDs {
		d := levenshtein(name, known)
		if d < bestDist {
			best, bestDist = known, d
		}
	}
	if bestDist > maxSuggestDistance {
		return ""
	}
	return best
}

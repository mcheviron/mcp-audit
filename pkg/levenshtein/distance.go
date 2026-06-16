package levenshtein

func Distance(a, b string) int {
	if len(a) > len(b) {
		a, b = b, a
	}

	if len(a) == 0 {
		return len(b)
	}

	prev := make([]int, len(a)+1)
	cur := make([]int, len(a)+1)

	for i := range prev {
		prev[i] = i
	}

	for j := 1; j <= len(b); j++ {
		cur[0] = j
		for i := 1; i <= len(a); i++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			cur[i] = min(
				prev[i]+1,
				cur[i-1]+1,
				prev[i-1]+cost,
			)
		}
		prev, cur = cur, prev
	}

	return prev[len(a)]
}

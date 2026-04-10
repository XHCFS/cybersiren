package normalization

// IsValidHexHash reports whether s is a valid lowercase hex string of exactly hexLen characters.
func IsValidHexHash(s string, hexLen int) bool {
	if len(s) != hexLen {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

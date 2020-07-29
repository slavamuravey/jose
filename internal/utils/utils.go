package utils

// contains checks if string is presented in slice
func Contains(needle string, haystack []string) bool {
  for _, item := range haystack {
    if item == needle {
      return true
    }
  }

  return false
}

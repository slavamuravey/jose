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

func Max(x, y int) int {
  if x > y {
    return x
  }
  return y
}

func Intersect(as, bs []string) []string {
  i := make([]string, 0, Max(len(as), len(bs)))
  for _, a := range as {
    for _, b := range bs {
      if a == b {
        i = append(i, a)
      }
    }
  }

  return i
}

func MapKeys(m map[string]interface{}) []string {
  keys := make([]string, 0, len(m))
  for k := range m {
    keys = append(keys, k)
  }

  return keys
}
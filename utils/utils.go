package utils

// IsGiant checks if a star is a giant based on its mass.
func IsGiant(mass float64) bool {
    return mass > 3.0
}

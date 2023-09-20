package api

import "fmt"

// Star represents a celestial object.
type Star struct {
    Name  string
    Type  string
    Mass  float64
}

// NewStar creates a new Star.
func NewStar(name, starType string, mass float64) Star {
    return Star{name, starType, mass}
}

// Info prints information about the Star.
func (s Star) Info() {
    fmt.Printf("Star Name: %s\nType: %s\nMass: %f\n", s.Name, s.Type, s.Mass)
}

package ports

import "time"

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Time{} }

type fixedIDGenerator struct{}

func (fixedIDGenerator) New() string { return "fixed-id" }

var _ Clock = fixedClock{}
var _ IDGenerator = fixedIDGenerator{}

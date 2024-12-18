package tss

type Round interface {
	Start() error
	Update() (bool, error)
	RoundNumber() int
	CanProceed() bool
	NextRound() Round
	DeviceId() string
}

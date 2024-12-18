package keygen

const (
	TaskName = "threshold-keygen"
)

type SaveData struct {
	PartyIndex int
	Data       []byte
}

type (
	base struct {
		n           int
		index       int
		sessionId   string
		sessionKind string
		deviceId    string
		devices     []string
		out         chan<- []byte
		end         chan<- *SaveData
		ok          []bool // `ok` tracks parties which have been verified by Update()
		started     bool
		number      int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	round4 struct {
		*round3
	}
)

func (round *base) DeviceId() string {
	return round.deviceId
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			return false
		}
	}
	return true
}

// ----- //

// `ok` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

// get ssid from local params
func (round *base) getSSID() ([]byte, error) {
	return []byte("keygen"), nil
}

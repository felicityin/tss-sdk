package auxiliary

import (
	"fmt"
	"strings"

	tssdk "tss-sdk/export"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
	"tss-sdk/tss/protocols/cggmp/auxiliary"
	"tss-sdk/tss/protocols/utils"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type SaveData struct {
	PartyIndex int
	Data       []byte
}

type (
	LocalParty struct {
		*tss.BaseParty

		n          int
		partyIndex int
		sessionId  string
		deviceId   string
		devices    []string

		// outbound messaging
		out chan<- []byte
		end chan<- *SaveData
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	logLevel string, // "info, debug, error"
	sessionId string,
	sessionKind string,
	deviceId string,
	allDevices string, // comma separated
	connIds string, // comma separated
	out chan<- []byte,
	end chan<- *SaveData,
) tss.Party {
	party := tssdk.NewAuxLocalParty(
		logLevel, sessionId, sessionKind, deviceId, allDevices, connIds,
	)
	if !party.Ok {
		common.Logger.Error(party.Err)
	}

	devices := strings.Split(allDevices, ",")
	index := utils.PartyIndex(deviceId, devices)
	common.Logger.Infof("index: %d", index)

	return &LocalParty{
		BaseParty:  new(tss.BaseParty),
		n:          len(strings.Split(allDevices, ",")),
		partyIndex: index,
		sessionId:  sessionId,
		deviceId:   deviceId,
		devices:    devices,
		out:        out,
		end:        end,
	}
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.n, p.partyIndex, p.sessionId, p.deviceId, p.devices, p.out, p.end)
}

func (p *LocalParty) Start() error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg []byte) (ok bool, err error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) StoreMessage(recv []byte) (bool, error) {
	msg, router, err := utils.ParseMpcMsg(recv, p.sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv msg err: %s", err.Error())
		return false, err
	}
	common.Logger.Infof("[Store] [%s] %s get msg from: %d", p.sessionId, router.Round, router.From.Index)

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *auxiliary.AuxRound1Message:
		res := tssdk.AuxRound1Accept(p.sessionId, recv)
		if !res.Ok {
			common.Logger.Errorf("TKeygenRound1Accept err: %s", res.Err)
			return false, fmt.Errorf("%s", res.Err)
		}
	case *auxiliary.AuxRound2Message:
		res := tssdk.AuxRound2Accept(p.sessionId, recv)
		if !res.Ok {
			common.Logger.Errorf("TKeygenRound2Accept1 err: %s", res.Err)
			return false, fmt.Errorf("%s", res.Err)
		}
	case *auxiliary.AuxRound3Message:
		res := tssdk.AuxRound3Accept(p.sessionId, recv)
		if !res.Ok {
			common.Logger.Errorf("TKeygenRound2Accept2 err: %s", res.Err)
			return false, fmt.Errorf("%s", res.Err)
		}
	default: // unrecognised message, just ignore!
		common.Logger.Warnf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyIndex() int {
	return p.partyIndex
}

func (p *LocalParty) PartyID() string {
	return p.deviceId
}

func (p *LocalParty) SessionID() string {
	return p.sessionId
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}

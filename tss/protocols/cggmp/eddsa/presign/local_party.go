package presign

import (
	"fmt"
	"math/big"

	"tss-sdk/tss/common"
	"tss-sdk/tss/protocols/cggmp/auxiliary"
	"tss-sdk/tss/protocols/cggmp/eddsa/sign"
	"tss-sdk/tss/protocols/cggmp/keygen"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		auxs auxiliary.LocalPartySaveData
		temp localTempData
		data LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *LocalPartySaveData
	}

	localMessageStore struct {
		signRound1Message1s,
		signRound1Message2s,
		signRound2Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		isThreshold bool

		// temp data (thrown away after sign) / round 1
		rho          *big.Int
		kCiphertexts []*big.Int

		ssid      []byte
		ssidNonce *big.Int
	}
)

func NewLocalParty(
	isThreshold bool,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	aux auxiliary.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- *LocalPartySaveData,
	fullBytesLen ...int,
) (tss.Party, error) {
	key, err := keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs())
	if err != nil {
		return nil, err
	}
	err = utils.UpdateKeyForSigning(&key, "", isThreshold, params.Threshold())
	if err != nil {
		return nil, err
	}

	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      key,
		auxs:      aux,
		temp:      localTempData{},
		data:      NewLocalPartySaveData(partyCount),
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.signRound1Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound1Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)

	p.temp.isThreshold = isThreshold
	p.temp.kCiphertexts = make([]*big.Int, partyCount)
	return p, nil
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.temp.isThreshold, p.params, &p.keys, &p.auxs, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if msg.GetFrom() == nil || !msg.GetFrom().ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("received msg with an invalid sender: %s", msg))
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := len(p.params.Parties().IDs()) - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	return p.BaseParty.ValidateMessage(msg)
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *sign.SignRound1Message1:
		p.temp.signRound1Message1s[fromPIdx] = msg

	case *sign.SignRound1Message2:
		p.temp.signRound1Message2s[fromPIdx] = msg

	case *sign.SignRound2Message:
		p.temp.signRound2Messages[fromPIdx] = msg

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}

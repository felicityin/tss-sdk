package keygen

import (
	"fmt"
	"math/big"

	"github.com/ipfs/go-log"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	cmt "tss-sdk/tss/crypto/commitments"
	"tss-sdk/tss/crypto/vss"
	save "tss-sdk/tss/protocols/cggmp/keygen"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		temp localTempData
		data save.LocalPartySaveData

		number int
		ok     []bool

		sessionId          string
		sessionKind        string
		deviceToPartyIndex map[string]int
	}

	localMessageStore struct {
		kgRound1Messages,
		kgRound2Message1s,
		kgRound2Message2s,
		kgRound3Messages []tss.ParsedMessage
	}

	sendMessageStore struct {
		kgRound2Message2s [][]byte // msg.WireBytes()
	}

	// temp data (thrown away after keygen)
	localTempData struct {
		localMessageStore
		send sendMessageStore

		s0            *big.Int
		KGCs          []cmt.HashCommitment
		vs            vss.Vs
		shares        vss.Shares
		deCommitPolyG cmt.HashDeCommitment
		chainCode     []byte // 32-bytes

		// ZKP Schnorr
		tau       *big.Int
		commitedA []*crypto.ECPoint

		// Echo broadcast and random oracle data seed
		srid []byte
		u    []byte

		ssid      []byte
		ssidNonce *big.Int

		V [][]byte
	}
)

var Parties = map[string]*LocalParty{}

// Exported, used in `tss` client
func NewLocalParty(
	algo string, // ecdsa or eddsa
	sessionId string,
	sessionKind string,
	deviceId string,
	allDevices []string,
	connIds []uint64,
	rootPrivKey string, // hex string
	chainCode string, // hex string
) (result utils.TssResult) {
	if err := log.SetLogLevel("tss-lib", "info"); err != nil {
		common.Logger.Errorf("set log level, err: %s", err.Error())
		result.Err = fmt.Sprintf("set log level, err: %s", err.Error())
		return
	}

	if algo == "ecdsa" {
		tss.SetCurve(tss.S256())
	} else if algo == "eddsa" {
		tss.SetCurve(tss.Edwards())
	} else {
		common.Logger.Errorf("unknown alog: %s", algo)
		result.Err = fmt.Sprintf("unknown alog: %s", algo)
		return
	}

	partyCount := len(allDevices)
	partyIndexs, pIds := utils.SortPartys(deviceId, allDevices, connIds)
	p2pCtx := tss.NewPeerContext(pIds)

	partyIndex := partyIndexs[deviceId]
	common.Logger.Infof("party index: %d", partyIndex)

	var params *tss.Parameters
	if algo == "ecdsa" {
		params = tss.NewParameters(tss.S256(), p2pCtx, pIds[partyIndex], partyCount, partyCount)
	} else if algo == "eddsa" {
		params = tss.NewParameters(tss.Edwards(), p2pCtx, pIds[partyIndex], partyCount, partyCount)
	} else {
		common.Logger.Errorf("unknown algo: %s", algo)
		result.Err = fmt.Sprintf("unknown algo: %s", algo)
		return
	}

	data := save.NewLocalPartySaveData(partyCount)
	p := &LocalParty{
		BaseParty:          new(tss.BaseParty),
		params:             params,
		temp:               localTempData{},
		data:               data,
		ok:                 make([]bool, partyCount),
		sessionId:          sessionId,
		sessionKind:        sessionKind,
		deviceToPartyIndex: partyIndexs,
	}

	// msgs init
	p.temp.kgRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound2Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound2Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.send.kgRound2Message2s = make([][]byte, partyCount)

	// temp data init
	p.temp.KGCs = make([]cmt.HashCommitment, partyCount)
	p.temp.commitedA = make([]*crypto.ECPoint, partyCount)
	p.temp.V = make([][]byte, partyCount)

	Parties[sessionId] = p
	result.Ok = true
	return
}

func GetParty(sessionId string) (*LocalParty, error) {
	party, ok := Parties[sessionId]
	if !ok {
		err := fmt.Errorf("party not found: %s", sessionId)
		common.Logger.Errorf("%s", err.Error())
		return nil, err
	}
	return party, nil
}

func RemoveParty(sessionId string) bool {
	if _, ok := Parties[sessionId]; !ok {
		return false
	}
	delete(Parties, sessionId)
	return true
}

func (p *LocalParty) resetOK() {
	for j := range p.ok {
		p.ok[j] = false
	}
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}

func (p *LocalParty) SetSecretX(x *big.Int) {
	p.data.PrivXi = x
}

func (p *LocalParty) SetChainCode(x *big.Int) {
	p.data.ChainCode = x
}

// get ssid from local params
func (p *LocalParty) getSSID() ([]byte, error) {
	return []byte("threshold-keygen"), nil
}

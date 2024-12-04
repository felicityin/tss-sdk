package keygen

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ipfs/go-log"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
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

		sessionId   string
		sessionKind string
		partyIndex  int
	}

	localMessageStore struct {
		kgRound1Messages,
		kgRound2Messages,
		kgRound3Messages []tss.ParsedMessage
	}

	// temp data (thrown away after keygen)
	localTempData struct {
		localMessageStore

		chainCode []byte // 32-bytes

		// ZKP Schnorr
		tau       *big.Int
		commitedA *crypto.ECPoint

		// Echo broadcast and random oracle data seed
		srid []byte
		u    []byte

		payload []*CmpKeyGenerationPayload

		ssid      []byte
		ssidNonce *big.Int

		V [][]byte
	}
)

type CmpKeyGenerationPayload struct {
	// Schnorr ZKP
	commitedA *crypto.ECPoint

	// Echo broadcast and random oracle data seed
	ssid []byte
	srid []byte
	u    []byte
}

type KeygenExecResult struct {
	Ok           bool   `json:"ok"`
	Err          string `json:"error"`
	MsgWireBytes []byte `json:"data"`
}

var Parties = map[string]*LocalParty{}

// Exported, used in `tss` client
func NewLocalParty(
	algo string, // ecdsa or eddsa
	sessionId string,
	sessionKind string,
	deviceId string,
	partyDevices []string,
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

	partyCount := len(partyDevices)
	partyIndexs, pIds := utils.SortPartys(deviceId, partyDevices, connIds)
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

	privkey, err := hex.DecodeString(rootPrivKey)
	if err != nil {
		result.Err = fmt.Sprintf("hex decode rootPrivKey, err:%s", err.Error())
		return
	}
	data.PrivXi = new(big.Int).SetBytes(privkey)

	chaincode, err := hex.DecodeString(chainCode)
	if err != nil {
		result.Err = fmt.Sprintf("hex decode chainCode, err:%s", err.Error())
		return
	}
	data.ChainCode = new(big.Int).SetBytes(chaincode)

	p := &LocalParty{
		BaseParty:   new(tss.BaseParty),
		params:      params,
		temp:        localTempData{},
		data:        data,
		ok:          make([]bool, partyCount),
		sessionId:   sessionId,
		sessionKind: sessionKind,
		partyIndex:  partyIndex,
	}

	// msgs init
	p.temp.kgRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound3Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	p.temp.payload = make([]*CmpKeyGenerationPayload, partyCount)
	p.temp.V = make([][]byte, partyCount)

	Parties[sessionId] = p
	result.Ok = true
	return
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
	return []byte("keygen"), nil
}

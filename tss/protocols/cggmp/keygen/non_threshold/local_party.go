package keygen

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ipfs/go-log"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	save "tss-sdk/tss/protocols/cggmp/keygen"
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
	}

	localMessageStore struct {
		kgRound1Messages,
		kgRound2Messages,
		kgRound3Messages [][]byte // msg.WireBytes()
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

type KeygenResult struct {
	Ok  bool   `json:"ok"`
	Err string `json:"error"`
}

var Parties = map[string]*LocalParty{}

// Exported, used in `tss` client
func NewLocalParty(
	key string,
	partyIndex int,
	partyCount int,
	pIDs []string,
	rootPrivKey string,
	chainCode string,
) (result KeygenResult) {
	if err := log.SetLogLevel("tss-lib", "info"); err != nil {
		common.Logger.Errorf("set log level, err: %s", err.Error())
		result.Err = fmt.Sprintf("set log level, err: %s", err.Error())
		return
	}
	tss.SetCurve(tss.Edwards())

	uIds := make(tss.UnSortedPartyIDs, 0, partyCount)
	for i := 0; i < partyCount; i++ {
		pId, _ := new(big.Int).SetString(pIDs[i], 10)
		common.Logger.Infof("id: %d", pId)
		uIds = append(uIds, tss.NewPartyID(fmt.Sprintf("%d", i), fmt.Sprintf("m_%d", i), pId))
	}
	ids := tss.SortPartyIDs(uIds)

	p2pCtx := tss.NewPeerContext(ids)
	params := tss.NewParameters(tss.Edwards(), p2pCtx, ids[partyIndex], partyCount, partyCount)
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
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		data:      data,
		ok:        make([]bool, partyCount),
	}

	// msgs init
	p.temp.kgRound1Messages = make([][]byte, partyCount)
	p.temp.kgRound2Messages = make([][]byte, partyCount)
	p.temp.kgRound3Messages = make([][]byte, partyCount)

	// temp data init
	p.temp.payload = make([]*CmpKeyGenerationPayload, partyCount)
	p.temp.V = make([][]byte, partyCount)

	Parties[key] = p
	result.Ok = true
	return
}

func RemoveParty(key string) bool {
	if _, ok := Parties[key]; !ok {
		return false
	}
	delete(Parties, key)
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

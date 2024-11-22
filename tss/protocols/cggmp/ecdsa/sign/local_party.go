package sign

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/protocols/cggmp/auxiliary"
	"tss-sdk/tss/protocols/cggmp/keygen"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"

	"github.com/ipfs/go-log"
)

// Implements Party
// Implements Stringer
// var _ tss.Party = (*LocalParty)(nil)
// var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		key    keygen.LocalPartySaveData
		aux    auxiliary.LocalPartySaveData
		temp   localTempData
		data   *common.SignatureData
		number int
		ok     []bool
	}

	localMessageStore struct {
		signRound1Message1s,
		signRound1Message2s,
		signRound2Messages,
		signRound3Messages,
		signRound4Messages []tss.ParsedMessage
	}

	sendMessageStore struct {
		signRound1Message2s,
		signRound2Messages,
		signRound3Messages [][]byte // msg.WireBytes()
	}

	localTempData struct {
		localMessageStore
		send sendMessageStore

		msg         *big.Int
		isThreshold bool

		// round 1
		k                *big.Int
		gamma            *big.Int
		kCiphertexts     []*big.Int
		gammaCiphertexts []*big.Int
		rho              *big.Int
		mu               *big.Int
		fullBytesLen     int

		// round 2
		beta    []*big.Int
		betaHat []*big.Int
		Gamma   *crypto.ECPoint

		// round 3
		sumGamma *crypto.ECPoint
		chi      *big.Int
		delta    *big.Int
		Delta    *crypto.ECPoint

		// round 4
		R  *crypto.ECPoint
		si *big.Int

		ssid      []byte
		ssidNonce *big.Int
	}
)

var SignParties = map[string]*LocalParty{}

func NewLocalParty(
	isThreshold bool,
	key string,
	partyIndex int,
	partyCount int,
	pIDs []string,
	msg string, // hex string
	keyData string, // keygen.LocalPartySaveData, base64 string
	auxData string, // auxiliary.LocalPartySaveData, base64 string
	walletPath string,
) (result utils.TssResult) {
	if err := log.SetLogLevel("tss-lib", "info"); err != nil {
		common.Logger.Errorf("set log level, err: %s", err.Error())
		result.Err = fmt.Sprintf("set log level, err: %s", err.Error())
		return
	}
	tss.SetCurve(tss.S256())

	common.Logger.Infof("wallet path: %s", walletPath)
	parts := strings.Split(walletPath, "/")
	if len(parts) != 5 {
		common.Logger.Errorf("wallet path err: %s", walletPath)
		result.Err = fmt.Sprintf("wallet path err: %s", walletPath)
		return
	}

	uIds := make(tss.UnSortedPartyIDs, 0, partyCount)
	for i := 0; i < partyCount; i++ {
		pId, _ := new(big.Int).SetString(pIDs[i], 10)
		common.Logger.Infof("id: %d", pId)
		uIds = append(uIds, tss.NewPartyID(fmt.Sprintf("%d", i), fmt.Sprintf("m_%d", i), pId))
	}
	ids := tss.SortPartyIDs(uIds)
	p2pCtx := tss.NewPeerContext(ids)
	params := tss.NewParameters(tss.S256(), p2pCtx, ids[partyIndex], partyCount, partyCount)

	keyDataBytes, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		common.Logger.Errorf("base64 decode keygen data fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("base64 decode keygen data fail, err:%s", err.Error())
		return
	}
	keySave := &keygen.LocalPartySaveData{}
	if err := json.Unmarshal(keyDataBytes, keySave); err != nil {
		common.Logger.Errorf("unmarshal keygen save data err: %s", err.Error())
		result.Err = fmt.Sprintf("unmarshal keygen save data err: %s", err.Error())
		return
	}
	keyParty, err := keygen.BuildLocalSaveDataSubset(*keySave, params.Parties().IDs())
	if err != nil {
		result.Err = fmt.Sprintf("BuildLocalSaveDataSubset err: %s", err.Error())
		common.Logger.Errorf("BuildLocalSaveDataSubset err: %s", err.Error())
		return
	}
	err = utils.UpdateKeyForSigning(&keyParty, walletPath, isThreshold, params.Threshold())
	if err != nil {
		result.Err = fmt.Sprintf("UpdateKeyForSigningh err: %s", err.Error())
		common.Logger.Errorf("UpdateKeyForSigningh err: %s", err.Error())
		return
	}
	common.Logger.Infof("keys.PubXj count: %d", len(keySave.PubXj))

	auxDataBytes, err := base64.StdEncoding.DecodeString(auxData)
	if err != nil {
		common.Logger.Errorf("base64 decode aux data fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("base64 decode aux data fail, err:%s", err.Error())
		return
	}
	auxSave := &auxiliary.LocalPartySaveData{}
	if err := json.Unmarshal(auxDataBytes, auxSave); err != nil {
		common.Logger.Errorf("unmarshal aux save data err: %s", err.Error())
		result.Err = fmt.Sprintf("unmarshal aux save data err: %s", err.Error())
		return
	}
	auxParty, err := auxiliary.BuildLocalSaveDataSubset(*auxSave, params.Parties().IDs())
	if err != nil {
		result.Err = fmt.Sprintf("BuildLocalSaveDataSubset err: %s", err.Error())
		common.Logger.Errorf("BuildLocalSaveDataSubset err: %s", err.Error())
		return
	}

	m, err := hex.DecodeString(msg)
	if err != nil {
		common.Logger.Errorf("hex decode msg err: %s", err.Error())
		result.Err = fmt.Sprintf("hex decode msg err: %s", err.Error())
		return
	}

	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		key:       keyParty,
		aux:       auxParty,
		temp:      localTempData{},
		data:      &common.SignatureData{},
		ok:        make([]bool, partyCount),
	}
	// msgs init
	p.temp.signRound1Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound1Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound4Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.send.signRound1Message2s = make([][]byte, partyCount)
	p.temp.send.signRound2Messages = make([][]byte, partyCount)
	p.temp.send.signRound3Messages = make([][]byte, partyCount)

	// temp data init
	p.temp.msg = new(big.Int).SetBytes(m)
	p.temp.isThreshold = isThreshold
	p.temp.kCiphertexts = make([]*big.Int, partyCount)
	p.temp.gammaCiphertexts = make([]*big.Int, partyCount)
	p.temp.beta = make([]*big.Int, partyCount)
	p.temp.betaHat = make([]*big.Int, partyCount)

	SignParties[key] = p
	result.Ok = true
	return
}

func RemoveSignParty(key string) bool {
	if _, ok := SignParties[key]; !ok {
		return false
	}
	delete(SignParties, key)
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

// get ssid from local params
func (round *LocalParty) getSSID() ([]byte, error) {
	return []byte("ecdsa-sign"), nil
}

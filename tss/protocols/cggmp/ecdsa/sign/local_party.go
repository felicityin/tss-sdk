package sign

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ipfs/go-log"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/protocols/cggmp/auxiliary"
	"tss-sdk/tss/protocols/cggmp/keygen"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

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

		sessionId          string
		sessionKind        string
		deviceToPartyIndex map[string]int
		index              int
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

var Parties = map[string]*LocalParty{}

func NewLocalParty(
	logLevel string, // "info, debug, error"
	threshold int,
	sessionId string,
	sessionKind string,
	deviceId string,
	allDevices []string,
	connIds []uint64,
	msg string, // hex string
	keyData string, // keygen.LocalPartySaveData, base64 string
	auxData string, // auxiliary.LocalPartySaveData, base64 string
	walletPath string,
) (result utils.TssResult) {
	if err := log.SetLogLevel("tss-lib", logLevel); err != nil {
		common.Logger.Errorf("set log level, err: %s", err.Error())
		result.Err = fmt.Sprintf("set log level, err: %s", err.Error())
		return
	}
	tss.SetCurve(tss.S256())

	isThreshold := true
	if threshold <= 0 {
		isThreshold = false
	}
	common.Logger.Infof("isThreshold: %t, %d", isThreshold, threshold)

	common.Logger.Infof("wallet path: %s", walletPath)
	parts := strings.Split(walletPath, "/")
	if len(parts) != 5 {
		common.Logger.Errorf("wallet path err: %s", walletPath)
		result.Err = fmt.Sprintf("wallet path err: %s", walletPath)
		return
	}

	partyCount := len(allDevices)
	partyIndexs, pIds := utils.SortPartys(deviceId, allDevices, connIds)
	p2pCtx := tss.NewPeerContext(pIds)

	partyIndex := partyIndexs[deviceId]
	common.Logger.Infof("party index: %d", partyIndex)

	params := tss.NewParameters(tss.S256(), p2pCtx, pIds[partyIndex], partyCount, threshold)

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
	common.Logger.Infof("privkey: %d", keyParty.PrivXi)
	for _, pk := range keyParty.PubXj {
		common.Logger.Infof("pk.X: %d", pk.X())
	}

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
		BaseParty:          new(tss.BaseParty),
		params:             params,
		key:                keyParty,
		aux:                auxParty,
		temp:               localTempData{},
		data:               &common.SignatureData{},
		ok:                 make([]bool, partyCount),
		sessionId:          sessionId,
		sessionKind:        sessionKind,
		deviceToPartyIndex: partyIndexs,
		index:              partyIndex,
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

func RemoveSignParty(sessionId string) bool {
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

// get ssid from local params
func (round *LocalParty) getSSID() ([]byte, error) {
	return []byte("ecdsa-sign"), nil
}

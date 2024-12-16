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
	"tss-sdk/tss/protocols/cggmp/keygen"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		temp localTempData
		data *common.SignatureData

		number int
		ok     []bool

		sessionId          string
		sessionKind        string
		deviceToPartyIndex map[string]int
	}

	localMessageStore struct {
		signRound1Messages,
		signRound2Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		isThreshold bool

		m            *big.Int
		r            *big.Int
		fullBytesLen int

		// round 1
		d *big.Int
		e *big.Int

		// round 2
		c  *big.Int
		Rj []*crypto.ECPoint
		si *[32]byte

		ssid      []byte
		ssidNonce *big.Int
	}
)

var SignParties = map[string]*LocalParty{}

func NewLocalParty(
	isThreshold bool,
	sessionId string,
	sessionKind string,
	deviceId string,
	allDevices []string,
	connIds []uint64,
	msg string, // hex string
	keyData string, // keygen.LocalPartySaveData, base64 string
	walletPath string,
) (result utils.TssResult) {
	if err := log.SetLogLevel("tss-lib", "info"); err != nil {
		common.Logger.Errorf("set log level, err: %s", err.Error())
		result.Err = fmt.Sprintf("set log level, err: %s", err.Error())
		return
	}
	tss.SetCurve(tss.Edwards())

	partyCount := len(allDevices)
	partyIndexs, pIds := utils.SortPartys(deviceId, allDevices, connIds)
	p2pCtx := tss.NewPeerContext(pIds)

	partyIndex := partyIndexs[deviceId]
	common.Logger.Infof("party index: %d", partyIndex)
	params := tss.NewParameters(tss.Edwards(), p2pCtx, pIds[partyIndex], partyCount, partyCount)

	keyDataBytes, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		common.Logger.Errorf("base64 decode keygen data fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("base64 decode keygen data fail, err:%s", err.Error())
		return
	}
	keys := keygen.LocalPartySaveData{}
	if err := json.Unmarshal(keyDataBytes, &keys); err != nil {
		common.Logger.Errorf("unmarshal keygen save data err: %s", err.Error())
		result.Err = fmt.Sprintf("unmarshal keygen save data err: %s", err.Error())
		return
	}

	common.Logger.Infof("wallet path: %s", walletPath)
	common.Logger.Infof("keys.PubXj count: %d", len(keys.PubXj))
	parts := strings.Split(walletPath, "/")
	if len(parts) != 5 {
		common.Logger.Errorf("wallet path err: %s", walletPath)
		result.Err = fmt.Sprintf("wallet path err: %s", walletPath)
		return
	}

	keyParty, err := keygen.BuildLocalSaveDataSubset(keys, params.Parties().IDs())
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

	p := &LocalParty{
		BaseParty:          new(tss.BaseParty),
		params:             params,
		keys:               keys,
		temp:               localTempData{},
		data:               &common.SignatureData{},
		ok:                 make([]bool, partyCount),
		sessionId:          sessionId,
		sessionKind:        sessionKind,
		deviceToPartyIndex: partyIndexs,
	}
	// msgs init
	p.temp.signRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	m, err := hex.DecodeString(msg)
	if err != nil {
		common.Logger.Errorf("hex decode msg err: %s", err.Error())
		result.Err = fmt.Sprintf("hex decode msg err: %s", err.Error())
		return
	}
	p.temp.m = new(big.Int).SetBytes(m)
	p.temp.isThreshold = isThreshold
	p.temp.Rj = make([]*crypto.ECPoint, partyCount)

	SignParties[sessionId] = p
	result.Ok = true
	return
}

func GetParty(sessionId string) (*LocalParty, error) {
	party, ok := SignParties[sessionId]
	if !ok {
		err := fmt.Errorf("party not found: %s", sessionId)
		common.Logger.Errorf("%s", err.Error())
		return nil, err
	}
	return party, nil
}

func RemoveSignParty(sessionId string) bool {
	if _, ok := SignParties[sessionId]; !ok {
		return false
	}
	delete(SignParties, sessionId)
	return true
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}

// `ok` tracks parties which have been verified by Update()
func (round *LocalParty) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

// get ssid from local params
func (round *LocalParty) getSSID() ([]byte, error) {
	return []byte("eddsa-sign"), nil
}

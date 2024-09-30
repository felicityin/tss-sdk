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
	"tss-sdk/tss/protocols/cggmp/keygen"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"

	"github.com/ipfs/go-log"
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
	}

	localMessageStore struct {
		signRound1Messages,
		signRound2Messages [][]byte // msg.WireBytes()
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

type OnsignExecResult struct {
	Ok           bool   `json:"ok"`
	Err          string `json:"error"`
	MsgWireBytes []byte `json:"data"`
}

type OnsignResult struct {
	Ok  bool   `json:"ok"`
	Err string `json:"error"`
}

var SignParties = map[string]*LocalParty{}

func NewLocalParty(
	isThreshold bool,
	key string,
	partyIndex int,
	partyCount int,
	pIDs []string,
	msg string, // hex string
	keyData string, // keygen.LocalPartySaveData, base64 string
	walletPath string,
) (result OnsignResult) {
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
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keys,
		temp:      localTempData{},
		data:      &common.SignatureData{},
		ok:        make([]bool, partyCount),
	}
	// msgs init
	p.temp.signRound1Messages = make([][]byte, partyCount)
	p.temp.signRound2Messages = make([][]byte, partyCount)

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

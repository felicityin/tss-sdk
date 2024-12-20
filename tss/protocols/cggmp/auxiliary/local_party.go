package auxiliary

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ipfs/go-log"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto/paillier"
	"tss-sdk/tss/crypto/prmproof"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		temp localTempData
		save LocalPartySaveData

		number int
		ok     []bool

		sessionId          string
		sessionKind        string
		deviceToPartyIndex map[string]int
		index              int
	}

	localMessageStore struct {
		auxRound1Messages,
		auxRound2Messages,
		auxRound3Messages []tss.ParsedMessage
	}

	sendMessageStore struct {
		auxRound3Messages [][]byte // msg.WireBytes()
	}

	localTempData struct {
		localMessageStore
		send sendMessageStore

		prmProof *prmproof.RingPederssenParameterMessage

		// Echo broadcast and random oracle data seed
		srid []byte
		u    []byte
		rho  []byte

		ssid      []byte
		ssidNonce *big.Int

		V [][]byte
	}
)

var Parties = map[string]*LocalParty{}

// Exported, used in `tss` client
func NewLocalParty(
	logLevel string, // "info, debug, error"
	sessionId string,
	deviceId string,
	allDevices []string,
	connIds []uint64,
) (result utils.TssResult) {
	if err := log.SetLogLevel("tss-lib", logLevel); err != nil {
		common.Logger.Errorf("set log level, err: %s", err.Error())
		result.Err = fmt.Sprintf("set log level, err: %s", err.Error())
		return
	}

	partyCount := len(allDevices)
	partyIndexs, pIds := utils.SortPartys(deviceId, allDevices, connIds)
	p2pCtx := tss.NewPeerContext(pIds)

	partyIndex := partyIndexs[deviceId]
	common.Logger.Infof("party index: %d", partyIndex)

	params := tss.NewParameters(nil, p2pCtx, pIds[partyIndex], partyCount, partyCount)

	p := &LocalParty{
		BaseParty:          new(tss.BaseParty),
		params:             params,
		temp:               localTempData{},
		save:               NewLocalPartySaveData(partyCount),
		ok:                 make([]bool, partyCount),
		sessionId:          sessionId,
		deviceToPartyIndex: partyIndexs,
		index:              partyIndex,
	}

	// msgs init
	p.temp.auxRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.auxRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.auxRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.send.auxRound3Messages = make([][]byte, partyCount)

	// temp data init
	p.temp.V = make([][]byte, partyCount)

	Parties[sessionId] = p
	result.Ok = true
	return
}

func RemoveAuxParty(sessionId string) bool {
	if _, ok := Parties[sessionId]; !ok {
		return false
	}
	delete(Parties, sessionId)
	return true
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

func (p *LocalParty) PaillierSK() *paillier.PrivateKey {
	return p.save.PaillierSK
}

func (p *LocalParty) SetPaillierSK(sk *paillier.PrivateKey) {
	p.save.PaillierSK = sk
}

func (p *LocalParty) resetOK() {
	for j := range p.ok {
		p.ok[j] = false
	}
}

// recovers a party's original index in the set of parties during keygen
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}

func (p *LocalParty) getSSID() ([]byte, error) {
	return []byte("auxiliary"), nil
}

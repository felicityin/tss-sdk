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
	}

	localMessageStore struct {
		auxRound1Messages,
		auxRound2Messages,
		auxRound3Messages [][]byte // msg.WireBytes()
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
	key string,
	partyIndex int,
	partyCount int,
	pIDs []string,
) (result utils.TssResult) {
	if err := log.SetLogLevel("tss-lib", "info"); err != nil {
		common.Logger.Errorf("set log level, err: %s", err.Error())
		result.Err = fmt.Sprintf("set log level, err: %s", err.Error())
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
	params := tss.NewParameters(nil, p2pCtx, ids[partyIndex], partyCount, partyCount)

	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		save:      NewLocalPartySaveData(partyCount),
		ok:        make([]bool, partyCount),
	}

	// msgs init
	p.temp.auxRound1Messages = make([][]byte, partyCount)
	p.temp.auxRound2Messages = make([][]byte, partyCount)
	p.temp.auxRound3Messages = make([][]byte, partyCount)
	p.temp.send.auxRound3Messages = make([][]byte, partyCount)

	// temp data init
	p.temp.V = make([][]byte, partyCount)

	Parties[key] = p
	result.Ok = true
	return
}

func RemoveAuxParty(key string) bool {
	if _, ok := Parties[key]; !ok {
		return false
	}
	delete(Parties, key)
	return true
}

func GetParty(key string) (*LocalParty, error) {
	party, ok := Parties[key]
	if !ok {
		err := fmt.Errorf("party not found: %s", key)
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

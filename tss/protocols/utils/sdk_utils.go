package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"

	"google.golang.org/protobuf/proto"

	"tss-sdk/msgs"
	"tss-sdk/tss/common"
	"tss-sdk/tss/tss"
)

type TssExecResult struct {
	Ok        bool   `json:"ok"`
	Err       string `json:"error"`
	Msg       []byte `json:"msg"`
	Pubkey    string `json:"pubkey"`    // hex string. only keygen return
	ChainCode string `json:"chainCode"` // hex string. only keygen return
}

type TssResult struct {
	Ok  bool   `json:"ok"`
	Err string `json:"error"`
}

type PeerId struct {
	id       *big.Int
	deviceId string
	connId   uint64
}

func partyId(peer string) *big.Int {
	h := sha256.New()
	h.Write([]byte(peer))
	return new(big.Int).SetBytes(h.Sum(nil))
}

func SortPartys(deviceId string, allDevices []string, connIds []uint64) (deviceToPartyIndex map[string]int, pids tss.SortedPartyIDs) {
	peers := make([]*PeerId, 0, len(allDevices))
	for i, peer := range allDevices {
		peers = append(peers, &PeerId{
			id:       partyId(peer),
			deviceId: peer,
			connId:   connIds[i],
		})
	}

	sort.Slice(peers, func(i, j int) bool {
		return peers[i].id.Cmp(peers[j].id) < 0
	})

	deviceToPartyIndex = make(map[string]int)
	ids := make(tss.SortedPartyIDs, 0, len(allDevices))
	for i, peer := range peers {
		id := tss.NewPartyID(
			strconv.FormatUint(uint64(peer.connId), 10),
			peer.deviceId,
			peer.id,
		)
		id.Index = i
		ids = append(ids, id)
		common.Logger.Infof("sorted peer, index: %d, device id: %s, conn id: %d, id: %d", id.Index, peer.deviceId, peer.connId, peer.id)

		deviceToPartyIndex[peer.deviceId] = i
	}
	return deviceToPartyIndex, ids
}

func PartyIndex(deviceId string, allDevices []string) int {
	peers := make([]*PeerId, 0, len(allDevices))
	for _, device := range allDevices {
		peers = append(peers, &PeerId{
			id:       partyId(device),
			deviceId: device,
		})
	}

	sort.Slice(peers, func(i, j int) bool {
		return peers[i].id.Cmp(peers[j].id) < 0
	})

	for i, peer := range peers {
		if peer.deviceId == deviceId {
			return i
		}
	}
	return -1
}

func MpcBroadcastMsg(sessionId, sessionKind string, router *tss.MessageRouting, data []byte) []byte {
	routerBytes, _ := json.Marshal(router)
	msgBytes, _ := proto.Marshal(&msgs.SessionMessageParams{
		SessionId:   sessionId,
		SessionKind: sessionKind,
		IsBroadcast: true,
		Router:      routerBytes,
		Msg:         data,
	})
	msg, _ := proto.Marshal(&msgs.WsMsg{
		Name:   msgs.SessionMsg,
		Params: msgBytes,
	})
	return msg
}

func MpcP2pMsg(sessionId, sessionKind, peerId string, router *tss.MessageRouting, data []byte) []byte {
	routerBytes, _ := json.Marshal(router)
	toConnId, _ := strconv.ParseUint(peerId, 0, 64)
	msgBytes, _ := proto.Marshal(&msgs.SessionMessageParams{
		SessionId:   sessionId,
		SessionKind: sessionKind,
		To:          toConnId,
		IsBroadcast: false,
		Router:      routerBytes,
		Msg:         data,
	})
	msg, _ := proto.Marshal(&msgs.WsMsg{
		Name:   msgs.SessionMsg,
		Params: msgBytes,
	})
	return msg
}

func ParseMpcMsg(recv []byte, sessionId string) (msg tss.ParsedMessage, router *tss.MessageRouting, err error) {
	wsMsg := &msgs.WsMsg{}
	if err = proto.Unmarshal(recv, wsMsg); err != nil {
		err = fmt.Errorf("proto unmarshal ws msg error: %s", err.Error())
		return
	}

	data := &msgs.SessionMessageParams{}
	if err = proto.Unmarshal(wsMsg.Params, data); err != nil {
		err = fmt.Errorf("proto unmarshal session params error: %s", err.Error())
		return
	}

	if err = json.Unmarshal(data.Router, &router); err != nil {
		err = fmt.Errorf("recive invaild router msg, err: %s", err.Error())
		return
	}
	common.Logger.Infof("[%s %s] recv msg from: %d %s %s", sessionId, router.Round, router.From.Index, router.From.Moniker, router.From.Id)

	msg, err = tss.ParseWireMessage(data.Msg, router.From, router.IsBroadcast)
	if err != nil {
		err = fmt.Errorf("parse wire msg err:%s", err.Error())
		return
	}
	return msg, router, nil
}

func ShouldAccept(router *tss.MessageRouting, index int) bool {
	return router.From.Index != index && (router.IsBroadcast || (!router.IsBroadcast && router.To[0].Index == index))
}

func ParseRecvMsg(msgWireBytes string) (msg tss.ParsedMessage, err error) {
	msgBytes, err := base64.StdEncoding.DecodeString(msgWireBytes)
	if err != nil {
		err = fmt.Errorf("base64 decode msg err: %s", err.Error())
		common.Logger.Errorf("%s", err.Error())
		return
	}

	msg, err = tss.ParseWireMsg(msgBytes)
	if err != nil {
		err = fmt.Errorf("parse wire msg err: %s", err.Error())
		common.Logger.Errorf("%s", err.Error())
		return
	}
	return msg, nil
}

func ParseWireMsg(msg []byte, name string) (tmsg tss.ParsedMessage, err error) {
	tmsg, err = tss.ParseWireMsg(msg)
	if err != nil {
		err = fmt.Errorf("parse %s wire msg err: %s", name, err.Error())
		common.Logger.Errorf("%s", err.Error())
		return
	}
	return tmsg, nil
}

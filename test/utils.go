// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package test

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/proto"

	"tss-sdk/msgs"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
	ts "tss-sdk/tss/tss"
)

func SharedPartyUpdater(party tss.Party, msg []byte, errCh chan<- error) {
	if _, err := party.Update(msg); err != nil {
		errCh <- err
	}
}

func SharedPartyUpdaterDebug(party tss.Party, msg []byte, errCh chan<- error) {
	router, err := ParseMpcMsg(msg, party.SessionID())
	if err != nil {
		common.Logger.Errorf("parse recv msg err: %s", err.Error())
	}

	if router.From.Index == party.PartyIndex() {
		if router.IsBroadcast {
			common.Logger.Infof("[test %s] drop broadcast msg from %d", router.Round, router.From.Index)
		} else {
			common.Logger.Infof("[test %s] drop p2p msg from %d", router.Round, router.From.Index)
		}
		return
	}

	if router.IsBroadcast {
		common.Logger.Infof("[test %s] reveive broadcast msg from %d", router.Round, router.From.Index)
		if _, err := party.Update(msg); err != nil {
			errCh <- err
		}
		return
	}

	if router.To[0].Index == party.PartyIndex() {
		common.Logger.Infof("[test %s] reveive p2p msg from %d, to: %d", router.Round, router.From.Index, router.To[0].Index)
		if _, err := party.Update(msg); err != nil {
			errCh <- err
		}
	}
}

func ParseMpcMsg(recv []byte, sessionId string) (router *ts.MessageRouting, err error) {
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
	return router, nil
}

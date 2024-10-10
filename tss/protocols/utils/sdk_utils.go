package utils

import (
	"encoding/base64"
	"fmt"
	"tss-sdk/tss/common"
	"tss-sdk/tss/tss"
)

type TssExecResult struct {
	Ok           bool   `json:"ok"`
	Err          string `json:"error"`
	MsgWireBytes []byte `json:"data"`
}

type TssResult struct {
	Ok  bool   `json:"ok"`
	Err string `json:"error"`
}

func ParseRecvMsg(msgWireBytes string) (msgBytes []byte, msg tss.ParsedMessage, err error) {
	msgBytes, err = base64.StdEncoding.DecodeString(msgWireBytes)
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
	return msgBytes, msg, nil
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

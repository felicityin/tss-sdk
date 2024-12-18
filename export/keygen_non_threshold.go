package tssdk

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	keygen "tss-sdk/tss/protocols/cggmp/keygen/non_threshold"
	"tss-sdk/tss/protocols/utils"
)

type MpcExecResult struct {
	Ok        bool   `json:"ok"`
	Err       string `json:"error"`
	Msg       []byte `json:"data"`
	Pubkey    string `json:"pubkey"`    // hex string. only keygen return
	ChainCode string `json:"chainCode"` // hex string. only keygen return
}

type MpcResult struct {
	Ok  bool   `json:"ok"`
	Err string `json:"error"`
}

func (result MpcExecResult) ToJson() string {
	b, _ := json.Marshal(result)
	return string(b)
}

func (result MpcResult) ToJson() string {
	b, _ := json.Marshal(result)
	return string(b)
}

func NewKeygenLocalParty(
	algo string, // ecdsa or eddsa
	sessionId string,
	sessionKind string,
	deviceId string,
	allDevices string, // comma separated
	connIds string, // comma separated
	rootPrivKey string, // hex string
	chainCode string, // hex string
) *MpcResult {
	parties, connectIds, err := parseParties(allDevices, connIds)
	if err != nil {
		return &MpcResult{Ok: false, Err: err.Error()}
	}
	res := keygen.NewLocalParty(algo, sessionId, sessionKind, deviceId, parties, connectIds, rootPrivKey, chainCode)
	return toMpcRes(res)
}

func RemoveKeygenParty(sessionId string) bool {
	return keygen.RemoveParty(sessionId)
}

func KeygenRound1Exec(sessionId string) *MpcExecResult {
	res := keygen.KeygenRound1Exec(sessionId)
	return toMpcExecRes(res)
}

func KeygenRound1Accept(sessionId string, recv []byte) *MpcResult {
	res := keygen.KeygenRound1Accept(sessionId, recv)
	return toMpcRes(res)
}

func KeygenRound1Finish(sessionId string) *MpcResult {
	res := keygen.KeygenRound1Finish(sessionId)
	return toMpcRes(res)
}

func KeygenRound2Exec(sessionId string) *MpcExecResult {
	res := keygen.KeygenRound2Exec(sessionId)
	return toMpcExecRes(res)
}

func KeygenRound2Accept(sessionId string, recv []byte) *MpcResult {
	res := keygen.KeygenRound2Accept(sessionId, recv)
	return toMpcRes(res)
}

func KeygenRound2Finish(sessionId string) *MpcResult {
	res := keygen.KeygenRound2Finish(sessionId)
	return toMpcRes(res)
}

func KeygenRound3Exec(sessionId string) *MpcExecResult {
	res := keygen.KeygenRound3Exec(sessionId)
	return toMpcExecRes(res)
}

func KeygenRound3Accept(sessionId string, recv []byte) *MpcResult {
	res := keygen.KeygenRound3Accept(sessionId, recv)
	return toMpcRes(res)
}

func KeygenRound3Finish(sessionId string) *MpcResult {
	res := keygen.KeygenRound3Finish(sessionId)
	return toMpcRes(res)
}

func KeygenRound4Exec(sessionId string) *MpcExecResult {
	res := keygen.KeygenRound4Exec(sessionId)
	return toMpcExecRes(res)
}

func toMpcExecRes(res utils.TssExecResult) *MpcExecResult {
	return &MpcExecResult{
		Ok:  res.Ok,
		Err: res.Err,
		Msg: res.Msg,
	}
}

func toMpcRes(res utils.TssResult) *MpcResult {
	return &MpcResult{
		Ok:  res.Ok,
		Err: res.Err,
	}
}

func parseParties(allDevices string, connIds string) ([]string, []uint64, error) {
	parties := strings.Split(allDevices, ",")
	connectIds := strings.Split(connIds, ",")

	if len(parties) != len(connectIds) {
		return nil, nil, fmt.Errorf("party devices: %d, connIds: %d, not equal", len(parties), len(connectIds))
	}

	conns := make([]uint64, 0)
	for _, connId := range connectIds {
		conn, err := strconv.ParseUint(connId, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("connId %s is not uint64: %s", connId, err.Error())
		}
		conns = append(conns, conn)
	}

	return parties, conns, nil
}

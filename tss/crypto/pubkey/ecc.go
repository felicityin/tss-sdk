package pubkey

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

func EncodeEcdsaPk(x *big.Int, y *big.Int) (string, error) {
	var xFieldVal btcec.FieldVal
	var yFieldVal btcec.FieldVal
	if overflow := xFieldVal.SetByteSlice(x.Bytes()); overflow {
		return "", fmt.Errorf("xFieldVal.SetByteSlice(pk.X.Bytes()) overflow: %d", x)
	}
	if overflow := yFieldVal.SetByteSlice(y.Bytes()); overflow {
		return "", fmt.Errorf("yFieldVal.SetByteSlice(pk.Y.Bytes()) overflow: %d", y)
	}
	pk := btcec.NewPublicKey(&xFieldVal, &yFieldVal)
	return hex.EncodeToString(pk.SerializeCompressed()), nil
}

func DecodeEcdsaPk(pk string) (*btcec.PublicKey, error) {
	pkBytes, err := hex.DecodeString(pk)
	if err != nil {
		return nil, fmt.Errorf("hex decode pk %s err: %s", pk, err.Error())
	}
	pt, err := btcec.ParsePubKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("btcec parse pk %s err: %s", pk, err.Error())
	}
	return pt, nil
}

func EncodeEddsaPk(x *big.Int, y *big.Int) string {
	pk := edwards.NewPublicKey(x, y)
	return hex.EncodeToString(pk.SerializeCompressed())
}

func DecodeEddsaPk(pk string) (*edwards.PublicKey, error) {
	pkBytes, err := hex.DecodeString(pk)
	if err != nil {
		return nil, fmt.Errorf("hex decode pk %s err: %s", pk, err.Error())
	}
	pt, err := edwards.ParsePubKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("edwards parse pk %s err: %s", pk, err.Error())
	}
	return pt, nil
}

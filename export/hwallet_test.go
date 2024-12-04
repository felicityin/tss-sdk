package tssdk

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"tss-sdk/tss/crypto"
	"tss-sdk/tss/tss"
)

func TestGenerateMnemonic(t *testing.T) {
	m := GenerateMnemonic(24)
	fmt.Printf("%s\n", m)

	words := strings.Split(m, " ")
	assert.Equal(t, len(words), 24)
}

func TestGetSignatureWithV(t *testing.T) {
	s := GetSignatureWithV(
		"14210474298522440080862268404868660084424802222226046880068802260488888866200",
		"76493066916257178868604648460428280266860860222622042084806666840020888404620",
		"67441279211242264626262006284820804266484246424468420644620464226080224422842",
		27,
	)
	assert.Equal(
		t,
		"1f6ad7eab8ff8f8654921c6d2194036f19f47b1b47c63911e311c6fefc1d55986ae596b364f275e087f65837c76fac1b313177d899f932ab9b5a227c0c4695871c",
		s,
	)
}

func Test_RemoveKeygenParty(t *testing.T) {
	RemoveKeygenParty("1")
}

func Test_checkAddress(t *testing.T) {
	var address = "1AZc1GsxG1jgb73XnZje4SZka3HwxHsTZe"
	var res = CheckAddress(address, "BCH")
	print(res)
}

func Test_GetSignature(t *testing.T) {
	var res = GetSignature(
		"307834313637373236353635323037343666323037333639363736653230373436383639373332303664363537333733363136373635",
		"307834313637373236353635323037343666323037333639363736653230373436383639373332303664363537333733363136373635",
		"307834313637373236353635323037343666323037333639363736653230373436383639373332303664363537333733363136373635")
	print(res)
}

func Test_GetSignatureHash(t *testing.T) {
	var res = GetSignatureHash("307834313637373236353635323037343666323037333639363736653230373436383639373332303664363537333733363136373635")
	print(res)
}

func Test_GeneratePubKey(t *testing.T) {
	pkX, _ := new(big.Int).SetString("b2d3f7d2e73401bfe239920292295909c8fe27b710f4165991f1759eff6f87f7", 16)
	pkY, _ := new(big.Int).SetString("08aefe3ad8c53528daa531cf5f5d86d861805a282f883b1a361868811deca05a", 16)
	point, err := crypto.NewECPoint(tss.S256(), pkX, pkY)

	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("04b2d3f7d2e73401bfe239920292295909c8fe27b710f4165991f1759eff6f87f708aefe3ad8c53528daa531cf5f5d86d861805a282f883b1a361868811deca05a")

	pt, err := point.MarshalJSON()
	fmt.Println(hex.EncodeToString(pt))

}

func Test_GenerateWallet(t *testing.T) {
	fmt.Println(GenerateMnemonic(12))
	fmt.Println(GetFingerPrint(GenerateMnemonic(24)))
	fmt.Println(GenerateMnemonic(24))
}

func Test_GenerateAddress(t *testing.T) {
	const pubKeyHex = "b2d3f7d2e73401bfe239920292295909c8fe27b710f4165991f1759eff6f87f7|08aefe3ad8c53528daa531cf5f5d86d861805a282f883b1a361868811deca05a"
	fmt.Println("BTC = ", GenerateAddress(pubKeyHex, "BTC"))
	fmt.Println("ETH = ", GenerateAddress(pubKeyHex, "ETH"))
	fmt.Println("LTC = ", GenerateAddress(pubKeyHex, "LTC"))
	fmt.Println("TRX = ", GenerateAddress(pubKeyHex, "TRX"))
	fmt.Println("DOGE = ", GenerateAddress(pubKeyHex, "DOGE"))
}

func Test_GeneratePathWallet(t *testing.T) {
	fmt.Println(GeneratePathWallet(GenerateMnemonic(12), "44/1").ToJson())
}

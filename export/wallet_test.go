package tssdk

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const mnemonic = "build motion fit gallery retire actress prosper mean cage tongue sausage shift certain track pudding company baby jelly call figure judge noble enroll connect"

func TestGenerateMnemonic(t *testing.T) {
	m := GenerateMnemonic(24)

	isValid := VaildMnemonic(m)
	assert.True(t, isValid)

	words := strings.Split(m, " ")
	assert.Equal(t, len(words), 24)
}

func TestGenFingerPrint(t *testing.T) {
	fingerPrint := GenFingerPrint(mnemonic).Result
	assert.Equal(t, fingerPrint, "6e43f10f564bc140355a249dad96b16605df4d4e")
}

func TestGenHardWalletPriv(t *testing.T) {
	pinCode := "123456"
	mnemonic := GenerateMnemonic(24)
	seed := MnemonicToSeed(mnemonic).Result

	privkey := GenHardWalletPriv(mnemonic, pinCode)
	privkey1 := GenHardWalletPrivBySeed(seed, pinCode)
	assert.Equal(t, privkey, privkey1)
}

func TestGenHardWalletFingerPrint(t *testing.T) {
	pinCode := "123456"
	mnemonic := GenerateMnemonic(24)
	seed := MnemonicToSeed(mnemonic).Result

	fingerPrint := GenHardWalletFingerPrint(mnemonic, pinCode).Result
	fingerPrint1 := GenHardWalletFingerPrintBySeed(seed, pinCode).Result
	assert.Equal(t, fingerPrint, fingerPrint1)
}

func Test_GetSignature(t *testing.T) {
	var res = GetSignature(
		"307834313637373236353635323037343666323037333639363736653230373436383639373332303664363537333733363136373635",
		"307834313637373236353635323037343666323037333639363736653230373436383639373332303664363537333733363136373635",
		"307834313637373236353635323037343666323037333639363736653230373436383639373332303664363537333733363136373635",
	)
	sig := "218e1b1e8be634a58eb349c73882f27cc0a03124160a61e6c902d1dbbd6bc733354dd457e5559bb363bd14a383218e1b1e8be634a58eb349c73782f27cc0a03124160a61e6c902d1dbbeb118564e9e8bb7a995c954d6ecde624202"
	assert.Equal(t, res, sig)
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
		s,
		"1f6ad7eab8ff8f8654921c6d2194036f19f47b1b47c63911e311c6fefc1d55986ae596b364f275e087f65837c76fac1b313177d899f932ab9b5a227c0c4695871c",
	)
}

func Test_RemoveKeygenParty(t *testing.T) {
	RemoveKeygenParty("1")
}

package hdwallet

import (
	"tss-sdk/hwallet/bip39"
	"tss-sdk/hwallet/bip39/wordlists"
)

func setLanguage(language string) {
	switch language {
	case English:
		bip39.SetWordList(wordlists.English)
	}
}

// NewMnemonic creates a random mnemonic
func NewMnemonic(length int, language string) (string, error) {
	setLanguage(language)

	if length < 12 {
		length = 12
	}

	if length > 24 {
		length = 24
	}

	entropy, err := bip39.NewEntropy(length / 3 * 32)
	if err != nil {
		return "", err
	}

	return bip39.NewMnemonic(entropy)
}

// NewSeed creates a hashed seed
func NewSeed(mnemonic, password, language string) ([]byte, error) {
	setLanguage(language)
	return bip39.NewSeedWithErrorChecking(mnemonic, password)
}

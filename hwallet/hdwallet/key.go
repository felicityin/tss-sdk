package hdwallet

import (
	"encoding/hex"
	"regexp"
	"strings"

	"tss-sdk/hwallet/blocktree/go-owcdrivers/owkeychain"
	"tss-sdk/hwallet/blocktree/go-owcrypt"
)

// Key struct
type Key struct {
	opt *Options

	Mnemonic string //助记词
	Seed     string //根种子
	Net      string
}

func (k *Key) GetWallet() (Wallet, error) {

	coin, ok := coins[k.opt.CoinType]
	if !ok {
		return nil, ErrCoinTypeUnknow
	}
	return coin(k), nil
}
func NewKey(opts ...Option) (*Key, error) {

	var (
		err error
		o   = newOptions(opts...)
	)
	if len(o.Mnemonic) > 0 {
		mm := strings.Replace(o.Mnemonic, " ", "", -1)
		//mm := o.Mnemonic

		if ok, _ := regexp.MatchString(`[\p{Hangul}]`, mm); ok { //韩文
			o.Language = "korean"

		}
		if ok, _ := regexp.MatchString(`[a-zA-Z]`, mm); ok { //英语
			o.Language = "english"
		}
		if ok, _ := regexp.MatchString(`[\p{Han}]`, mm); ok { //中文
			o.Language = "chinese_simplified"
		}
	}
	//fmt.Println("o.Language = ", o.Language)
	if len(o.Seed) <= 0 {
		o.Seed, err = NewSeed(o.Mnemonic, o.Password, o.Language)
	}
	if err != nil {
		return nil, err
	}

	key := &Key{
		opt:      o,
		Mnemonic: o.Mnemonic,
		Seed:     hex.EncodeToString(o.Seed),
		Net:      o.Net,
	}

	err = key.init()
	if err != nil {
		return nil, err
	}

	return key, nil
}
func (k *Key) init() error {
	return nil
}

// GetChildKey return a key from master key
// params: [Purpose], [CoinType], [Account], [Change], [AddressIndex], [Path]

func DerivePathFromSeed(masterSeed []byte, path string) (prv []byte, err error) {
	//path := "m/44'/88'"
	pkey, err := owkeychain.DerivedPrivateKeyWithPath(masterSeed, path, owcrypt.ECC_CURVE_SECP256K1)
	if err != nil {
		return nil, err
	} else {
		return pkey.GetPrivateKeyBytes()
	}
}

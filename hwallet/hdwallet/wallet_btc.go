package hdwallet

func init() {
	coins[BTC] = newBTC
}

type btc struct {
	name   string
	symbol string
	key    *Key
}

func newBTC(key *Key) Wallet {
	return &btc{
		name:   "Bitcoin",
		symbol: "BTC",
		key:    key,
	}
}
func (c *btc) GetType() uint32 {
	return c.key.opt.CoinType
}

func (c *btc) GetName() string {
	return c.name
}

func (c *btc) GetKey() *Key {
	return c.key
}
func (c *btc) SignRawTransaction(signIn *SignInput) (*SignResult, error) {
	return &SignResult{
		ResCode: 0,
	}, nil
}

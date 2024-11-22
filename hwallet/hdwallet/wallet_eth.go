package hdwallet

func init() {
	coins[ETH] = newETH
}

type eth struct {
	name   string
	symbol string
	key    *Key
}

func newETH(key *Key) Wallet {
	return &eth{
		name:   "Ethereum",
		symbol: "ETH",
		key:    key,
	}
}
func (c *eth) GetType() uint32 {
	return c.key.opt.CoinType
}

func (c *eth) GetName() string {
	return c.name
}

func (c *eth) GetKey() *Key {
	return c.key
}
func (c *eth) SignRawTransaction(signIn *SignInput) (*SignResult, error) {
	return &SignResult{
		ResCode: 0,
	}, nil
}

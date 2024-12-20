package sign

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	"tss-sdk/msgs"
	"tss-sdk/test"
	keygen "tss-sdk/test/keygen_threshold"
	"tss-sdk/tss/common"
)

const (
	// To change these parameters, you must first delete the text fixture files in test/_fixtures/ and then run the keygen test alone.
	// Then the signing and resharing tests will work with the new n, t configuration using the newly written fixture files.
	TestParticipants = 3
	TestThreshold    = 2
)

func TestE2EThresholdConcurrent(t *testing.T) {
	n := TestThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(keygen.Eddsa, n, TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, n, len(keys))
	assert.Equal(t, n, len(signPIDs))

	const (
		sessionId = "sign"
		msg       = "00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5"
		path      = "0/1/2/2/10"
	)
	var (
		allDevices []string
		connIds    []string
	)

	allDevices = make([]string, n)
	connIds = make([]string, n)

	for i := 0; i < n; i++ {
		allDevices[i] = fmt.Sprintf("%d", i)
		connIds[i] = fmt.Sprintf("%d", i)
	}

	errCh := make(chan error, n)
	outCh := make(chan []byte, n+n)
	endCh := make(chan *SaveData, n)

	parties := make([]*LocalParty, n, n)
	updater := test.SharedPartyUpdaterDebug

	// init the parties
	for i := 0; i < n; i++ {
		key, err := json.Marshal(keys[i])
		assert.NoError(t, err)

		keyData := base64.StdEncoding.EncodeToString(key)

		party := NewLocalParty(
			"debug",
			TestThreshold,
			fmt.Sprintf("%s-%s", sessionId, allDevices[i]),
			msgs.SessionKindEddsaSign,
			allDevices[i],
			strings.Join(allDevices, ","),
			strings.Join(connIds, ","),
			msg,
			keyData,
			path,
			outCh,
			endCh,
		).(*LocalParty)
		parties[i] = party

		go func(party *LocalParty) {
			if err := party.Start(); err != nil {
				errCh <- err
			}
		}(party)
	}

	var ended int32
signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			for _, P := range parties {
				go updater(P, msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				t.Log("EDDSA signing test done.")
				// END EDDSA verify
				break signing
			}
		}
	}
}

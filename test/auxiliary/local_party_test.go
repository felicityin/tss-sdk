package auxiliary

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"tss-sdk/msgs"
	"tss-sdk/test"
	"tss-sdk/tss/common"
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrentAndSaveFixtures(t *testing.T) {
	setUp("debug")

	const (
		sessionId = "aux"
		deviceId  = "test-device"
	)
	var (
		allDevices []string
		connIds    []string
	)

	n := TestParticipants

	allDevices = make([]string, n)
	connIds = make([]string, n)

	for i := 0; i < n; i++ {
		allDevices[i] = fmt.Sprintf("%s-%d", deviceId, i)
		connIds[i] = fmt.Sprintf("%d", i)
	}

	errCh := make(chan error, n)
	outCh := make(chan []byte, n+n)
	endCh := make(chan *SaveData, n)

	parties := make([]*LocalParty, n, n)
	updater := test.SharedPartyUpdater
	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < n; i++ {
		party := NewLocalParty(
			fmt.Sprintf("%s-%s", sessionId, allDevices[i]),
			msgs.SessionKindEcdsaAux,
			allDevices[i],
			strings.Join(allDevices, ","),
			strings.Join(connIds, ","),
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
AUX:
	for {
		common.Logger.Debugf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break AUX

		case msg := <-outCh:
			for _, P := range parties {
				go updater(P, msg, errCh)
			}

		case save := <-endCh:
			common.Logger.Debugf("reveive save data")

			tryWriteTestFixtureFile(t, save.PartyIndex, save.Data)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(n) {
				t.Logf("Done. Received save data from %d participants", ended)
				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())
				break AUX
			}
		}
	}
}

func tryWriteTestFixtureFile(t *testing.T, index int, data []byte) {
	fixtureFileName := makeTestFixtureFilePath(index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}

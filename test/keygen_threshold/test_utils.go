package keygen

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/pkg/errors"

	"tss-sdk/tss/common"
	save "tss-sdk/tss/protocols/cggmp/keygen"
	"tss-sdk/tss/tss"
)

const (
	Ecdsa = 0
	Eddsa = 1
)

const (
	testFixtureDirFormat       = "%s/../data/keygen_threshold"
	testEcdsaFixtureFileFormat = "ecdsa_keygen_%d.json"
	testEddsaFixtureFileFormat = "eddsa_keygen_%d.json"
)

func LoadKeygenTestFixtures(kind, qty int, optionalStart ...int) ([]save.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]save.LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(kind, i)
		common.Logger.Debugf("path: %s", fixtureFilePath)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key save.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		keys = append(keys, key)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	for i, key := range keys {
		pMoniker := fmt.Sprintf("%d", i+start+1)
		partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return keys, sortedPIDs, nil
}

func LoadKeygenTestFixturesRandomSet(kind, qty, fixtureCount int) ([]save.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]save.LocalPartySaveData, 0, qty)
	plucked := make(map[int]interface{}, qty)
	for i := 0; len(plucked) < qty; i = (i + 1) % fixtureCount {
		plucked[i] = new(struct{})
	}
	for i := range plucked {
		fixtureFilePath := makeTestFixtureFilePath(kind, i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key save.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		keys = append(keys, key)
	}

	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	j := 0
	for i := range plucked {
		key := keys[j]
		pMoniker := fmt.Sprintf("%d", i)
		partyIDs[j] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
		j++
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ShareID.Cmp(keys[j].ShareID) < 0 })
	return keys, sortedPIDs, nil
}

func makeTestFixtureFilePath(kind int, partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)
	if kind == Ecdsa {
		return fmt.Sprintf("%s/"+testEcdsaFixtureFileFormat, fixtureDirName, partyIndex)
	}
	return fmt.Sprintf("%s/"+testEddsaFixtureFileFormat, fixtureDirName, partyIndex)
}

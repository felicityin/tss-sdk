package auxiliary

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"

	"tss-sdk/tss/common"
	"tss-sdk/tss/tss"
)

const (
	// To change these parameters, you must first delete the text fixture files in test/_fixtures/ and then run the keygen test alone.
	// Then the signing and resharing tests will work with the new n, t configuration using the newly written fixture files.
	TestParticipants = 2
)
const (
	testFixtureDirFormat  = "%s/../data/auxiliary"
	testFixtureFileFormat = "auxiliary_%d.json"
)

func LoadAuxTestFixtures(kind, qty int, optionalStart ...int) ([]SaveData, tss.SortedPartyIDs, error) {
	auxs := make([]SaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(i)
		common.Logger.Infof("path: %s", fixtureFilePath)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var aux SaveData
		if err = json.Unmarshal(bz, &aux); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		auxs = append(auxs, aux)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(auxs))
	// for i, key := range auxs {
	// 	pMoniker := fmt.Sprintf("%d", i+start+1)
	// 	partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	// }
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return auxs, sortedPIDs, nil
}

func makeTestFixtureFilePath(partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}

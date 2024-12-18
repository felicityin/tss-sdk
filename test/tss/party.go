// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"errors"
	"fmt"
	"sync"

	"tss-sdk/tss/common"
)

type Party interface {
	Start() error
	// The main entry point when updating a party's state from the wire.
	// isBroadcast should represent whether the message was received via a reliable broadcast
	// UpdateFromBytes(wireBytes []byte, from *PartyID, isBroadcast bool) (ok bool, err error)
	// You may use this entry point to update a party's state when running locally or in tests
	Update(msg []byte) (ok bool, err error)
	Running() bool
	StoreMessage(msg []byte) (bool, error)
	FirstRound() Round
	PartyID() string
	PartyIndex() int
	SessionID() string
	String() string

	// Private lifecycle methods
	setRound(Round) error
	round() Round
	advance()
	lock()
	unlock()
}

type BaseParty struct {
	mtx        sync.Mutex
	rnd        Round
	FirstRound Round
}

func (p *BaseParty) Running() bool {
	return p.rnd != nil
}

func (p *BaseParty) String() string {
	return fmt.Sprintf("round: %d", p.round().RoundNumber())
}

// -----
// Private lifecycle methods

func (p *BaseParty) setRound(round Round) error {
	if p.rnd != nil {
		return errors.New("a round is already set on this party")
	}
	p.rnd = round
	return nil
}

func (p *BaseParty) round() Round {
	return p.rnd
}

func (p *BaseParty) advance() {
	p.rnd = p.rnd.NextRound()
}

func (p *BaseParty) lock() {
	p.mtx.Lock()
}

func (p *BaseParty) unlock() {
	p.mtx.Unlock()
}

// ----- //

func BaseStart(p Party, task string, prepare ...func(Round) error) error {
	p.lock()
	defer p.unlock()

	if p.round() != nil {
		return errors.New("could not start. this party is in an unexpected state. use the constructor and Start()")
	}

	round := p.FirstRound()
	if err := p.setRound(round); err != nil {
		return err
	}

	if 1 < len(prepare) {
		return errors.New("too many prepare functions given to Start(); 1 allowed")
	}
	if len(prepare) == 1 {
		if err := prepare[0](round); err != nil {
			return err
		}
	}

	common.Logger.Infof("party %s: %s round %d starting", p.round().DeviceId(), task, 1)
	defer func() {
		common.Logger.Infof("party %s: %s round %d finished", p.round().DeviceId(), task, 1)
	}()
	return p.round().Start()
}

// an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p Party, msg []byte, task string) (ok bool, err error) {
	// lock the mutex. need this mtx unlock hook; L108 is recursive so cannot use defer
	r := func(ok bool, err error) (bool, error) {
		p.unlock()
		return ok, err
	}
	p.lock() // data is written to P state below
	common.Logger.Debugf("party %s received message", p.PartyID())
	if p.round() != nil {
		common.Logger.Debugf("party %s round %d update", p.PartyID(), p.round().RoundNumber())
	}
	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.round() != nil {
		common.Logger.Debugf("party %s: %s round %d update", p.round().DeviceId(), task, p.round().RoundNumber())
		if _, err := p.round().Update(); err != nil {
			return r(false, err)
		}
		if p.round().CanProceed() {
			if p.advance(); p.round() != nil {
				if err := p.round().Start(); err != nil {
					return r(false, err)
				}
				rndNum := p.round().RoundNumber()
				common.Logger.Infof("party %s: %s round %d started", p.round().DeviceId(), task, rndNum)
			} else {
				// finished! the round implementation will have sent the data through the `end` channel.
				common.Logger.Infof("party %s: %s finished!", p.PartyID(), task)
			}
			p.unlock()                      // recursive so can't defer after return
			return BaseUpdate(p, msg, task) // re-run round update or finish)
		}
		return r(true, nil)
	}
	return r(true, nil)
}

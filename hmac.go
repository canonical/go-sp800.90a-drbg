// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package drbg

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"hash"
	"io"

	"golang.org/x/xerrors"
)

type hmacDRBG struct {
	h crypto.Hash

	v             []byte
	key           []byte
	reseedCounter uint64
}

func (d *hmacDRBG) update(providedData []byte) {
	h := hmac.New(func() hash.Hash { return d.h.New() }, d.key)
	h.Write(d.v)
	h.Write([]byte{0x00})
	h.Write(providedData)
	d.key = h.Sum(nil)

	h = hmac.New(func() hash.Hash { return d.h.New() }, d.key)
	h.Write(d.v)
	d.v = h.Sum(nil)

	if len(providedData) == 0 {
		return
	}

	h = hmac.New(func() hash.Hash { return d.h.New() }, d.key)
	h.Write(d.v)
	h.Write([]byte{0x01})
	h.Write(providedData)
	d.key = h.Sum(nil)

	h = hmac.New(func() hash.Hash { return d.h.New() }, d.key)
	h.Write(d.v)
	d.v = h.Sum(nil)
}

func (d *hmacDRBG) instantiate(entropyInput, nonce, personalization []byte, securityStrength int) {
	var seedMaterial bytes.Buffer
	seedMaterial.Write(entropyInput)
	seedMaterial.Write(nonce)
	seedMaterial.Write(personalization)

	d.key = make([]byte, d.h.Size())
	d.v = make([]byte, d.h.Size())
	for i := range d.v {
		d.v[i] = 0x01
	}

	d.update(seedMaterial.Bytes())
	d.reseedCounter = 1
}

func (d *hmacDRBG) reseed(entropyInput, additionalInput []byte) {
	var seedMaterial bytes.Buffer
	seedMaterial.Write(entropyInput)
	seedMaterial.Write(additionalInput)

	d.update(seedMaterial.Bytes())
	d.reseedCounter = 1
}

func (d *hmacDRBG) generate(additionalInput, data []byte) error {
	if d.reseedCounter > 1<<48 {
		return ErrReseedRequired
	}

	if len(additionalInput) > 0 {
		d.update(additionalInput)
	}

	var res bytes.Buffer

	for res.Len() < len(data) {
		h := hmac.New(func() hash.Hash { return d.h.New() }, d.key)
		h.Write(d.v)
		d.v = h.Sum(nil)

		res.Write(d.v)
	}

	copy(data, res.Bytes())

	d.update(additionalInput)
	d.reseedCounter += 1

	return nil
}

// NewHMAC creates a new HMAC based DRBG as specified in section 10.1.2 of SP-800-90A.
// The DRBG uses the supplied hash algorithm.
//
// The optional personalization argument is combined with entropy input to derive the
// initial seed. This argument can be used to differentiate this instantiation from others.
//
// The optional entropySource argument allows the default entropy source (rand.Reader from
// the crypto/rand package) to be overridden.
func NewHMAC(h crypto.Hash, personalization []byte, entropySource io.Reader) (*DRBG, error) {
	d := &DRBG{impl: &hmacDRBG{h: h}}
	if err := d.instantiate(personalization, entropySource, h.Size()/2); err != nil {
		return nil, xerrors.Errorf("cannot instantiate: %w", err)
	}

	return d, nil
}

// NewHMACWithExternalEntropy creates a new hash based DRBG as specified in section
// 10.1.2 of SP-800-90A. The DRBG uses the supplied hash algorithm. The entropyInput and
// nonce arguments provide the initial entropy to seed the created DRBG.
//
// The optional personalization argument is combined with entropy input to derive the
// initial seed. This argument can be used to differentiate this instantiation from others.
//
// The optional entropySource argument provides the entropy source for future reseeding. If
// it is not supplied, then the DRBG can only be reseeded with externally supplied entropy.
func NewHMACWithExternalEntropy(h crypto.Hash, entropyInput, nonce, personalization []byte, entropySource io.Reader) (*DRBG, error) {
	d := &DRBG{impl: &hmacDRBG{h: h}}
	if err := d.instantiateWithExternalEntropy(entropyInput, nonce, personalization, entropySource, h.Size()/2); err != nil {
		return nil, err
	}
	return d, nil
}

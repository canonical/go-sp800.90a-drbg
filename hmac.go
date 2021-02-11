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

func NewHMACDRBG(h crypto.Hash, personalization []byte, entropySource io.Reader) (*DRBG, error) {
	// TODO: Limit the length of personalization to 2^35bits
	d := &DRBG{impl: &hmacDRBG{h: h}}
	if err := d.instantiate(personalization, entropySource, h.Size()/2); err != nil {
		return nil, xerrors.Errorf("cannot instantiate: %w", err)
	}

	return d, nil
}

func NewHMACDRBGWithExternalEntropy(h crypto.Hash, entropyInput, nonce, personalization []byte, entropySource io.Reader) *DRBG {
	// TODO: Limit the length of personalization to 2^35bits
	d := &DRBG{impl: &hmacDRBG{h: h}}
	d.instantiateWithExternalEntropy(entropyInput, nonce, personalization, entropySource, h.Size()/2)
	return d
}

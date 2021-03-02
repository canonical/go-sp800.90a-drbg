// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package drbg implements several DRBGs as recommended by NIST SP-800-90A (see
http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf).

The hash, HMAC and block cipher mode DRBGs are implemented.

DRBG instances are automatically reseeded once the current seed period
expires.

All DRBGs are instantiated with the maximum security strength associated
with the requested configuration. The security strength cannot be specified
via the API.

DRBGs are instantiated by default using the platform's default entropy source
(via the crypto/rand package). This entropy source can be overridden, but it
must provide truly random data in order to achieve the selected security
strength.

Note that prediction resistance is not implemented. Prediction resistance
requires that the supplied entropy source is non-deterministic.
*/
package drbg

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"golang.org/x/xerrors"
)

// ErrReseedRequired indicates that the DRBG must be reseeded before
// it can generate random bytes.
var ErrReseedRequired = errors.New("the DRGB must be reseeded")

func zeroExtendBytes(x *big.Int, l int) (out []byte) {
	out = make([]byte, l)
	tmp := x.Bytes()
	copy(out[len(out)-len(tmp):], tmp)
	return
}

type drbgImpl interface {
	instantiate(entropyInput, nonce, personalization []byte, securityStrength int)
	reseed(entropyInput, additionalInput []byte)
	generate(additionalInput, data []byte) error
}

// DRBG corresponds to an instantiated DRBG based on one of the mechanisms specified
// in SP-800-90A.
type DRBG struct {
	entropySource    io.Reader
	securityStrength int
	impl             drbgImpl
}

func (d *DRBG) instantiate(personalization []byte, entropySource io.Reader, securityStrength int) error {
	if int64(len(personalization)) > 1<<32 {
		return errors.New("personalization too large")
	}

	d.entropySource = rand.Reader
	if entropySource != nil {
		d.entropySource = entropySource
	}

	d.securityStrength = securityStrength

	entropyInput := make([]byte, securityStrength)
	if _, err := d.entropySource.Read(entropyInput); err != nil {
		return xerrors.Errorf("cannot get entropy: %w", err)
	}

	nonce := make([]byte, securityStrength/2)
	if _, err := d.entropySource.Read(nonce); err != nil {
		return xerrors.Errorf("cannot get nonce: %w", err)
	}

	d.impl.instantiate(entropyInput, nonce, personalization, securityStrength)
	return nil
}

func (d *DRBG) instantiateWithExternalEntropy(entropyInput, nonce, personalization []byte, entropySource io.Reader, securityStrength int) error {
	if len(entropyInput) < securityStrength {
		return errors.New("entropyInput too small")
	}
	if int64(len(entropyInput)) > 1<<32 {
		return errors.New("entropyInput too large")
	}
	if int64(len(personalization)) > 1<<32 {
		return errors.New("personalization too large")
	}

	d.entropySource = entropySource
	d.securityStrength = securityStrength
	d.impl.instantiate(entropyInput, nonce, personalization, securityStrength)
	return nil
}

// ReseedWithExternalEntropy will reseed the DRBG with the supplied entropy.
func (d *DRBG) ReseedWithExternalEntropy(entropyInput, additionalInput []byte) error {
	if len(entropyInput) < d.securityStrength {
		return errors.New("entropyInput too small")
	}
	if int64(len(entropyInput)) > 1<<32 {
		return errors.New("entropyInput too large")
	}
	if int64(len(additionalInput)) > 1<<32 {
		return errors.New("additionalInput too large")
	}
	d.impl.reseed(entropyInput, additionalInput)
	return nil
}

// Reseed will reseed the DRBG with additional entropy using the entropy source
// it was initialized with.
func (d *DRBG) Reseed(additionalInput []byte) error {
	if int64(len(additionalInput)) > 1<<32 {
		return errors.New("additionalInput too large")
	}

	if d.entropySource == nil {
		return errors.New("cannot reseed without external entropy")
	}

	entropyInput := make([]byte, d.securityStrength)
	if _, err := d.entropySource.Read(entropyInput); err != nil {
		return xerrors.Errorf("cannot get entropy: %w", err)
	}

	d.impl.reseed(entropyInput, additionalInput)
	return nil
}

// Generate will fill the supplied data buffer with random bytes.
//
// If the DRBG needs to be reseeded before it can generate random bytes and it
// has been initialized with a source of entropy, the reseed operation will be
// performed automatically. If the DRBG hasn't been initialized with a source of
// entropy and it needs to be reseeded, ErrNeedsReseed will be returned.
//
// If the length of data is greater than 65536 bytes, an error will be returned.
func (d *DRBG) Generate(additionalInput, data []byte) error {
	if int64(len(additionalInput)) > 1<<32 {
		return errors.New("additionalInput too large")
	}

	if len(data) > 65536 {
		return errors.New("too many bytes requested")
	}

	for {
		err := d.impl.generate(additionalInput, data)
		switch {
		case err == ErrReseedRequired && d.entropySource != nil:
			if err := d.Reseed(additionalInput); err != nil {
				return xerrors.Errorf("cannot reseed: %w", err)
			}
			additionalInput = nil
		case err == ErrReseedRequired:
			return err
		case err != nil:
			return xerrors.Errorf("cannot generate random data: %w", err)
		default:
			return nil
		}
	}
}

// Read will read len(data) random bytes in to data.
//
// If the DRBG needs to be reseeded in order to generate all of the random bytes
// and it has been initialized with a source of entropy, the reseed operation will
// be performed automatically. If the DRBG hasn't been initialized with a source of
// entropy and it needs to be reseeded, ErrNeedsReseed will be returned.
func (d *DRBG) Read(data []byte) (int, error) {
	total := 0

	for len(data) > 0 {
		b := data
		if len(data) > 65536 {
			b = data[:65536]
		}

		if err := d.Generate(nil, b); err != nil {
			return total, err
		}

		total += len(b)
		data = data[len(b):]
	}

	return total, nil
}

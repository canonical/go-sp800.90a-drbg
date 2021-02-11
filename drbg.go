package drbg

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"golang.org/x/xerrors"
)

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

type DRBG struct {
	entropySource    io.Reader
	securityStrength int
	impl             drbgImpl
}

func (d *DRBG) instantiate(personalization []byte, entropySource io.Reader, securityStrength int) error {
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

func (d *DRBG) instantiateWithExternalEntropy(entropyInput, nonce, personalization []byte, entropySource io.Reader, securityStrength int) {
	d.entropySource = entropySource
	d.securityStrength = securityStrength
	d.impl.instantiate(entropyInput, nonce, personalization, securityStrength)
}

func (d *DRBG) ReseedWithExternalEntropy(entropyInput, additionalInput []byte) {
	// TODO: Limit the length of additionalInput to 2^35bits
	d.impl.reseed(entropyInput, additionalInput)
}

func (d *DRBG) Reseed(additionalInput []byte) error {
	if d.entropySource == nil {
		return errors.New("cannot reseed without external entropy")
	}

	// TODO: Limit the length of additionalInput to 2^35bits
	entropyInput := make([]byte, d.securityStrength)
	if _, err := d.entropySource.Read(entropyInput); err != nil {
		return xerrors.Errorf("cannot get entropy: %w", err)
	}

	d.impl.reseed(entropyInput, additionalInput)
	return nil
}

func (d *DRBG) Generate(additionalInput, data []byte) error {
	// TODO: Limit the length of additionalInput to 2^35bits
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

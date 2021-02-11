package drbg

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/xerrors"
)

var (
	dfKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
)

func block_encrypt(key, data []byte) (out []byte) {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("cannot create cipher: %v", err))
	}

	out = make([]byte, len(data))
	c.Encrypt(out, data)
	return
}

func bcc(key, data []byte) (out []byte) {
	out = make([]byte, aes.BlockSize)
	n := len(data) / aes.BlockSize

	for i := 0; i < n; i++ {
		input := make([]byte, aes.BlockSize)
		for j := 0; j < len(input); j++ {
			input[j] = out[j] ^ data[(i*aes.BlockSize)+j]
		}
		out = block_encrypt(key, input)
	}

	return
}

func block_cipher_df(keyLen int, input []byte, requestedBytes int) []byte {
	var s bytes.Buffer
	binary.Write(&s, binary.BigEndian, uint32(len(input)))
	binary.Write(&s, binary.BigEndian, uint32(requestedBytes))
	s.Write(input)
	s.Write([]byte{0x80})

	for s.Len()%aes.BlockSize != 0 {
		s.Write([]byte{0x00})
	}

	var temp bytes.Buffer

	k := dfKey[:keyLen]
	i := uint32(0)

	for temp.Len() < (keyLen + aes.BlockSize) {
		iv := make([]byte, aes.BlockSize)
		binary.BigEndian.PutUint32(iv, i)

		var data bytes.Buffer
		data.Write(iv)
		data.Write(s.Bytes())

		temp.Write(bcc(k, data.Bytes()))

		i += 1
	}

	k = make([]byte, keyLen)
	copy(k, temp.Bytes()[:keyLen])
	x := make([]byte, aes.BlockSize)
	copy(x, temp.Bytes()[keyLen:keyLen+aes.BlockSize])

	temp.Reset()

	for temp.Len() < requestedBytes {
		x = block_encrypt(k, x)
		temp.Write(x)
	}

	return temp.Bytes()[:requestedBytes]
}

type ctrDRBG struct {
	v             []byte
	key           []byte
	reseedCounter uint64
}

func (d *ctrDRBG) update(providedData []byte) {
	seedLength := len(d.v) + len(d.key)
	var temp bytes.Buffer

	one := big.NewInt(1)
	mod := new(big.Int)
	mod.Exp(big.NewInt(2), big.NewInt(int64(len(d.v)*8)), nil)

	for temp.Len() < seedLength {
		v := new(big.Int).SetBytes(d.v)
		v.Add(v, one)
		v.Mod(v, mod)
		d.v = zeroExtendBytes(v, len(d.v))

		temp.Write(block_encrypt(d.key, d.v))
	}

	temp.Truncate(seedLength)
	for i := 0; i < temp.Len(); i++ {
		temp.Bytes()[i] ^= providedData[i]
	}

	d.key = temp.Bytes()[:len(d.key)]
	d.v = temp.Bytes()[len(d.key):]
}

func (d *ctrDRBG) instantiate(entropyInput, nonce, personalization []byte, securityStrength int) {
	var seedMaterial bytes.Buffer
	seedMaterial.Write(entropyInput)
	seedMaterial.Write(nonce)
	seedMaterial.Write(personalization)

	seedLength := aes.BlockSize + len(d.key)

	d.v = make([]byte, aes.BlockSize)

	seed := block_cipher_df(len(d.key), seedMaterial.Bytes(), seedLength)
	d.update(seed)

	d.reseedCounter = 1
}

func (d *ctrDRBG) reseed(entropyInput, additionalInput []byte) {
	var seedMaterial bytes.Buffer
	seedMaterial.Write(entropyInput)
	seedMaterial.Write(additionalInput)

	seedLength := len(d.v) + len(d.key)
	seed := block_cipher_df(len(d.key), seedMaterial.Bytes(), seedLength)
	d.update(seed)

	d.reseedCounter = 1
}

func (d *ctrDRBG) generate(additionalInput, data []byte) error {
	if d.reseedCounter > 1<<48 {
		return ErrReseedRequired
	}

	seedLength := len(d.v) + len(d.key)

	if len(additionalInput) > 0 {
		additionalInput = block_cipher_df(len(d.key), additionalInput, seedLength)
		d.update(additionalInput)
	} else {
		additionalInput = make([]byte, seedLength)
	}

	var temp bytes.Buffer

	one := big.NewInt(1)
	mod := new(big.Int)
	mod.Exp(big.NewInt(2), big.NewInt(int64(len(d.v)*8)), nil)

	for temp.Len() < len(data) {
		v := new(big.Int).SetBytes(d.v)
		v.Add(v, one)
		v.Mod(v, mod)
		d.v = zeroExtendBytes(v, len(d.v))

		temp.Write(block_encrypt(d.key, d.v))
	}

	copy(data, temp.Bytes())

	d.update(additionalInput)
	d.reseedCounter += 1

	return nil
}

func NewCTRDRBG(keyLen int, personalization []byte, entropySource io.Reader) (*DRBG, error) {
	switch keyLen {
	case 16, 24, 32:
	default:
		return nil, errors.New("invalid key size")
	}

	// TODO: Limit the length of personalization to 2^35bits
	d := &DRBG{impl: &ctrDRBG{key: make([]byte, keyLen)}}
	if err := d.instantiate(personalization, entropySource, keyLen); err != nil {
		return nil, xerrors.Errorf("cannot instantiate: %w", err)
	}

	return d, nil
}

func NewCTRDRBGWithExternalEntropy(keyLen int, entropyInput, nonce, personalization []byte, entropySource io.Reader) (*DRBG, error) {
	switch keyLen {
	case 16, 24, 32:
	default:
		return nil, errors.New("invalid key size")
	}

	// TODO: Limit the length of personalization to 2^35bits
	d := &DRBG{impl: &ctrDRBG{key: make([]byte, keyLen)}}
	d.instantiateWithExternalEntropy(entropyInput, nonce, personalization, entropySource, keyLen)
	return d, nil
}

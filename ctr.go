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

type blockCipher interface {
	encrypt(key, data []byte) []byte
	blockSize() int
}

type aesBlockCipherImpl struct{}

var aesBlockCipher = aesBlockCipherImpl{}

func (b aesBlockCipherImpl) encrypt(key, data []byte) (out []byte) {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("cannot create cipher: %v", err))
	}

	out = make([]byte, len(data))
	c.Encrypt(out, data)
	return
}

func (b aesBlockCipherImpl) blockSize() int {
	return aes.BlockSize
}

func bcc(b blockCipher, key, data []byte) (out []byte) {
	out = make([]byte, b.blockSize())
	n := len(data) / b.blockSize()

	for i := 0; i < n; i++ {
		input := make([]byte, b.blockSize())
		for j := 0; j < len(input); j++ {
			input[j] = out[j] ^ data[(i*b.blockSize())+j]
		}
		out = b.encrypt(key, input)
	}

	return
}

func block_cipher_df(b blockCipher, keyLen int, input []byte, requestedBytes int) []byte {
	var s bytes.Buffer
	binary.Write(&s, binary.BigEndian, uint32(len(input)))
	binary.Write(&s, binary.BigEndian, uint32(requestedBytes))
	s.Write(input)
	s.Write([]byte{0x80})

	for s.Len()%b.blockSize() != 0 {
		s.Write([]byte{0x00})
	}

	var temp bytes.Buffer

	k := dfKey[:keyLen]
	i := uint32(0)

	for temp.Len() < (keyLen + b.blockSize()) {
		iv := make([]byte, b.blockSize())
		binary.BigEndian.PutUint32(iv, i)

		var data bytes.Buffer
		data.Write(iv)
		data.Write(s.Bytes())

		temp.Write(bcc(b, k, data.Bytes()))

		i += 1
	}

	k = make([]byte, keyLen)
	copy(k, temp.Bytes()[:keyLen])
	x := make([]byte, b.blockSize())
	copy(x, temp.Bytes()[keyLen:keyLen+b.blockSize()])

	temp.Reset()

	for temp.Len() < requestedBytes {
		x = b.encrypt(k, x)
		temp.Write(x)
	}

	return temp.Bytes()[:requestedBytes]
}

type ctrDRBG struct {
	b blockCipher

	v             []byte
	key           []byte
	reseedCounter uint64
}

func (d *ctrDRBG) keyLen() int {
	return len(d.key)
}

func (d *ctrDRBG) blockSize() int {
	return d.b.blockSize()
}

func (d *ctrDRBG) update(providedData []byte) {
	seedLength := d.blockSize() + d.keyLen()
	var temp bytes.Buffer

	one := big.NewInt(1)
	mod := new(big.Int)
	mod.Exp(big.NewInt(2), big.NewInt(int64(d.blockSize()*8)), nil)

	for temp.Len() < seedLength {
		v := new(big.Int).SetBytes(d.v)
		v.Add(v, one)
		v.Mod(v, mod)
		d.v = zeroExtendBytes(v, d.blockSize())

		temp.Write(d.b.encrypt(d.key, d.v))
	}

	temp.Truncate(seedLength)
	for i := 0; i < temp.Len(); i++ {
		temp.Bytes()[i] ^= providedData[i]
	}

	d.key = temp.Bytes()[:d.keyLen()]
	d.v = temp.Bytes()[d.keyLen():]
}

func (d *ctrDRBG) instantiate(entropyInput, nonce, personalization []byte, securityStrength int) {
	var seedMaterial bytes.Buffer
	seedMaterial.Write(entropyInput)
	seedMaterial.Write(nonce)
	seedMaterial.Write(personalization)

	seedLength := d.blockSize() + d.keyLen()

	seed := block_cipher_df(d.b, d.keyLen(), seedMaterial.Bytes(), seedLength)
	d.v = make([]byte, d.blockSize())
	d.update(seed)

	d.reseedCounter = 1
}

func (d *ctrDRBG) reseed(entropyInput, additionalInput []byte) {
	var seedMaterial bytes.Buffer
	seedMaterial.Write(entropyInput)
	seedMaterial.Write(additionalInput)

	seedLength := d.blockSize() + d.keyLen()
	seed := block_cipher_df(d.b, d.keyLen(), seedMaterial.Bytes(), seedLength)
	d.update(seed)

	d.reseedCounter = 1
}

func (d *ctrDRBG) generate(additionalInput, data []byte) error {
	if d.reseedCounter > 1<<48 {
		return ErrReseedRequired
	}

	seedLength := d.blockSize() + d.keyLen()

	if len(additionalInput) > 0 {
		additionalInput = block_cipher_df(d.b, d.keyLen(), additionalInput, seedLength)
		d.update(additionalInput)
	} else {
		additionalInput = make([]byte, seedLength)
	}

	var temp bytes.Buffer

	one := big.NewInt(1)
	mod := new(big.Int)
	mod.Exp(big.NewInt(2), big.NewInt(int64(d.blockSize()*8)), nil)

	for temp.Len() < len(data) {
		v := new(big.Int).SetBytes(d.v)
		v.Add(v, one)
		v.Mod(v, mod)
		d.v = zeroExtendBytes(v, d.blockSize())

		temp.Write(d.b.encrypt(d.key, d.v))
	}

	copy(data, temp.Bytes())

	d.update(additionalInput)
	d.reseedCounter += 1

	return nil
}

// NewCTRDRBG creates a new block cipher based DRBG as specified in section 10.2 of SP-800-90A.
// The DRBG uses the AES block cipher.
//
// The optional personalization argument is combined with entropy input to derive the
// initial seed. This argument can be used to differentiate this instantiation from others.
//
// The optional entropySource argument allows the default entropy source (rand.Reader from
// the crypto/rand package) to be overridden.
func NewCTRDRBG(keyLen int, personalization []byte, entropySource io.Reader) (*DRBG, error) {
	switch keyLen {
	case 16, 24, 32:
	default:
		return nil, errors.New("invalid key size")
	}

	// TODO: Limit the length of personalization to 2^35bits
	d := &DRBG{impl: &ctrDRBG{b: aesBlockCipher, key: make([]byte, keyLen)}}
	if err := d.instantiate(personalization, entropySource, keyLen); err != nil {
		return nil, xerrors.Errorf("cannot instantiate: %w", err)
	}

	return d, nil
}

// NewCTRDRBGWithExternalEntropy creates a new block cipher based DRBG as specified in
// section 10.2 of SP-800-90A. The DRBG uses the AES block cipher. The entropyInput and
// nonce arguments provide the initial entropy to seed the created DRBG.
//
// The optional personalization argument is combined with entropy input to derive the
// initial seed. This argument can be used to differentiate this instantiation from others.
//
// The optional entropySource argument provides the entropy source for future reseeding. If
// it is not supplied, then the DRBG can only be reseeded with externally supplied entropy.
func NewCTRDRBGWithExternalEntropy(keyLen int, entropyInput, nonce, personalization []byte, entropySource io.Reader) (*DRBG, error) {
	switch keyLen {
	case 16, 24, 32:
	default:
		return nil, errors.New("invalid key size")
	}

	// TODO: Limit the length of personalization to 2^35bits
	d := &DRBG{impl: &ctrDRBG{b: aesBlockCipher, key: make([]byte, keyLen)}}
	d.instantiateWithExternalEntropy(entropyInput, nonce, personalization, entropySource, keyLen)
	return d, nil
}

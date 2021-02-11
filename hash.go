package drbg

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/xerrors"
)

var (
	modulus55 = [56]byte{0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00}
	modulus111 = [112]byte{0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00}
)

func seedLength(h crypto.Hash) (int, error) {
	switch h {
	case crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA512_224, crypto.SHA512_256:
		return 55, nil
	case crypto.SHA384, crypto.SHA512:
		return 111, nil
	default:
		return 0, fmt.Errorf("unsupported digest algorithm: %v", h)
	}
}

func hash_gen(alg crypto.Hash, v []byte, requestedBytes int) []byte {
	n := (requestedBytes + (alg.Size() - 1)) / alg.Size()

	data := v
	var res bytes.Buffer

	one := big.NewInt(1)
	mod := new(big.Int)
	switch len(v) {
	case 55:
		mod.SetBytes(modulus55[:])
	case 111:
		mod.SetBytes(modulus111[:])
	default:
		panic("unexpected seed length")
	}

	for i := 1; i <= n; i++ {
		h := alg.New()
		h.Write(data)

		res.Write(h.Sum(nil))

		newData := new(big.Int).SetBytes(data)
		newData.Add(newData, one)
		newData.Mod(newData, mod)

		data = zeroExtendBytes(newData, len(v))
	}

	return res.Bytes()[:requestedBytes]
}

func hash_df(alg crypto.Hash, input []byte, requestedBytes int) []byte {
	n := (requestedBytes + (alg.Size() - 1)) / alg.Size()
	if n > 0xff {
		panic("invalid requested bytes")
	}

	requestedBits := uint32(requestedBytes * 8)

	var res bytes.Buffer

	for i := uint8(1); i <= uint8(n); i++ {
		h := alg.New()
		h.Write([]byte{i})
		binary.Write(h, binary.BigEndian, requestedBits)
		h.Write(input)

		res.Write(h.Sum(nil))
	}

	return res.Bytes()[:requestedBytes]
}

type hashDRBG struct {
	h crypto.Hash

	v             []byte
	c             []byte
	reseedCounter uint64
}

func (d *hashDRBG) seedLen() int {
	return len(d.v)
}

func (d *hashDRBG) instantiate(entropyInput, nonce, personalization []byte, securityStrength int) {
	var seedMaterial bytes.Buffer
	seedMaterial.Write(entropyInput)
	seedMaterial.Write(nonce)
	seedMaterial.Write(personalization)

	seed := hash_df(d.h, seedMaterial.Bytes(), d.seedLen())
	d.v = seed

	d.c = hash_df(d.h, append([]byte{0x00}, seed...), d.seedLen())

	d.reseedCounter = 1
}

func (d *hashDRBG) reseed(entropyInput, additionalInput []byte) {
	var seedMaterial bytes.Buffer
	seedMaterial.Write([]byte{0x01})
	seedMaterial.Write(d.v)
	seedMaterial.Write(entropyInput)
	seedMaterial.Write(additionalInput)

	seed := hash_df(d.h, seedMaterial.Bytes(), d.seedLen())
	d.v = seed

	d.c = hash_df(d.h, append([]byte{0x00}, seed...), d.seedLen())

	d.reseedCounter = 1
}

func (d *hashDRBG) generate(additionalInput, data []byte) error {
	if d.reseedCounter > 1<<48 {
		return ErrReseedRequired
	}

	mod := new(big.Int)
	switch d.seedLen() {
	case 55:
		mod.SetBytes(modulus55[:])
	case 111:
		mod.SetBytes(modulus111[:])
	default:
		panic("unexpected seed length")
	}

	if len(additionalInput) > 0 {
		h := d.h.New()
		h.Write([]byte{0x02})
		h.Write(d.v)
		h.Write(additionalInput)

		v := new(big.Int).SetBytes(d.v)
		v.Add(v, new(big.Int).SetBytes(h.Sum(nil)))
		v.Mod(v, mod)
		d.v = zeroExtendBytes(v, d.seedLen())
	}

	returnedBytes := hash_gen(d.h, d.v, len(data))
	copy(data, returnedBytes)

	hash := d.h.New()
	hash.Write([]byte{0x03})
	hash.Write(d.v)
	h := hash.Sum(nil)

	v := new(big.Int).SetBytes(d.v)
	v.Add(v, new(big.Int).SetBytes(h))
	v.Add(v, new(big.Int).SetBytes(d.c))
	v.Add(v, big.NewInt(int64(d.reseedCounter)))
	v.Mod(v, mod)

	d.v = zeroExtendBytes(v, d.seedLen())
	d.reseedCounter += 1

	return nil
}

// NewHash creates a new hash based DRBG as specified in section 10.1.1 of SP-800-90A.
// The DRBG uses the supplied hash algorithm.
//
// The optional personalization argument is combined with entropy input to derive the
// initial seed. This argument can be used to differentiate this instantiation from others.
//
// The optional entropySource argument allows the default entropy source (rand.Reader from
// the crypto/rand package) to be overridden.
func NewHash(h crypto.Hash, personalization []byte, entropySource io.Reader) (*DRBG, error) {
	seedLen, err := seedLength(h)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute seed length: %w", err)
	}
	// TODO: Limit the length of personalization to 2^35bits
	d := &DRBG{impl: &hashDRBG{h: h, v: make([]byte, seedLen)}}
	if err := d.instantiate(personalization, entropySource, h.Size()/2); err != nil {
		return nil, xerrors.Errorf("cannot instantiate: %w", err)
	}

	return d, nil
}

// NewHashWithExternalEntropy creates a new hash based DRBG as specified in section
// 10.1.1 of SP-800-90A. The DRBG uses the supplied hash algorithm. The entropyInput and
// nonce arguments provide the initial entropy to seed the created DRBG.
//
// The optional personalization argument is combined with entropy input to derive the
// initial seed. This argument can be used to differentiate this instantiation from others.
//
// The optional entropySource argument provides the entropy source for future reseeding. If
// it is not supplied, then the DRBG can only be reseeded with externally supplied entropy.
func NewHashWithExternalEntropy(h crypto.Hash, entropyInput, nonce, personalization []byte, entropySource io.Reader) (*DRBG, error) {
	seedLen, err := seedLength(h)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute seed length: %w", err)
	}
	// TODO: Limit the length of personalization to 2^35bits
	d := &DRBG{impl: &hashDRBG{h: h, v: make([]byte, seedLen)}}
	d.instantiateWithExternalEntropy(entropyInput, nonce, personalization, entropySource, h.Size()/2)
	return d, nil
}

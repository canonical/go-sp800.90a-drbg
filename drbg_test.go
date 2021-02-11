package drbg_test

import (
	"crypto"
	"encoding/hex"
	"io"
	"testing"

	. "github.com/chrisccoulson/go-sp800.90a-drbg"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

func decodeHexString(c *C, s string) []byte {
	x, err := hex.DecodeString(s)
	c.Assert(err, IsNil)
	return x
}

type drbgSuite struct{}

var _ = Suite(&drbgSuite{})

type entropySource struct {
	data []byte
}

func (s *entropySource) Read(data []byte) (int, error) {
	if len(s.data) == 0 {
		return 0, io.EOF
	}

	n := copy(data, s.data)
	s.data = s.data[n:]
	return n, nil
}

func makeEntropySource(data ...[]byte) (out *entropySource) {
	out = &entropySource{}
	for _, d := range data {
		out.data = append(out.data, d...)
	}
	return
}

type testData struct {
	entropyInput       []byte
	nonce              []byte
	personalization    []byte
	entropyInputReseed []byte
	additionalInput1   []byte
	additionalInput2   []byte
	expected           []byte
}

func (s *drbgSuite) testHash(c *C, h crypto.Hash, data *testData) {
	d, err := NewHashDRBGWithExternalEntropy(h, data.entropyInput, data.nonce, data.personalization, nil)
	c.Assert(err, IsNil)

	r := make([]byte, len(data.expected))
	n, err := d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	n, err = d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	c.Check(r, DeepEquals, data.expected)
}

func (s *drbgSuite) testHashAfterReseed(c *C, h crypto.Hash, data *testData) {
	d, err := NewHashDRBGWithExternalEntropy(h, data.entropyInput, data.nonce, data.personalization, nil)
	c.Assert(err, IsNil)

	d.ReseedWithExternalEntropy(data.entropyInputReseed, nil)

	r := make([]byte, len(data.expected))
	n, err := d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	n, err = d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	c.Check(r, DeepEquals, data.expected)
}

func (s *drbgSuite) testHMAC(c *C, h crypto.Hash, data *testData) {
	d := NewHMACDRBGWithExternalEntropy(h, data.entropyInput, data.nonce, data.personalization, nil)

	r := make([]byte, len(data.expected))
	n, err := d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	n, err = d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	c.Check(r, DeepEquals, data.expected)
}

func (s *drbgSuite) testHMACAfterReseed(c *C, h crypto.Hash, data *testData) {
	d := NewHMACDRBGWithExternalEntropy(h, data.entropyInput, data.nonce, data.personalization, nil)

	d.ReseedWithExternalEntropy(data.entropyInputReseed, nil)

	r := make([]byte, len(data.expected))
	n, err := d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	n, err = d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	c.Check(r, DeepEquals, data.expected)
}

func (s *drbgSuite) testCTR(c *C, keyLen int, data *testData) {
	d, err := NewCTRDRBGWithExternalEntropy(keyLen, data.entropyInput, data.nonce, data.personalization, nil)
	c.Assert(err, IsNil)

	r := make([]byte, len(data.expected))
	n, err := d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	n, err = d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	c.Check(r, DeepEquals, data.expected)
}

func (s *drbgSuite) testCTRAfterReseed(c *C, keyLen int, data *testData) {
	d, err := NewCTRDRBGWithExternalEntropy(keyLen, data.entropyInput, data.nonce, data.personalization, nil)
	c.Assert(err, IsNil)

	d.ReseedWithExternalEntropy(data.entropyInputReseed, nil)

	r := make([]byte, len(data.expected))
	n, err := d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	n, err = d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	c.Check(r, DeepEquals, data.expected)
}

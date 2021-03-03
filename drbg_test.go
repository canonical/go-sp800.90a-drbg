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
	entropyInput          []byte
	nonce                 []byte
	personalization       []byte
	entropyInputReseed    []byte
	additionalInputReseed []byte
	additionalInput       [2][]byte
	expected              []byte
}

func (s *drbgSuite) newHash(c *C, h crypto.Hash, data *testData) *DRBG {
	d, err := NewHashWithExternalEntropy(h, data.entropyInput, data.nonce, data.personalization, nil)
	c.Assert(err, IsNil)

	return d
}

func (s *drbgSuite) newHMAC(c *C, h crypto.Hash, data *testData) *DRBG {
	d, err := NewHMACWithExternalEntropy(h, data.entropyInput, data.nonce, data.personalization, nil)
	c.Assert(err, IsNil)

	return d
}

func (s *drbgSuite) newCTR(c *C, keyLen int, data *testData) *DRBG {
	d, err := NewCTRWithExternalEntropy(keyLen, data.entropyInput, data.nonce, data.personalization, nil)
	c.Assert(err, IsNil)

	return d
}

func (s *drbgSuite) testRead(c *C, d *DRBG, data *testData) {
	r := make([]byte, len(data.expected))
	n, err := d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))

	n, err = d.Read(r)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(r))
	c.Check(r, DeepEquals, data.expected)
}

func (s *drbgSuite) testReadAfterReseed(c *C, d *DRBG, data *testData) {
	d.ReseedWithExternalEntropy(data.entropyInputReseed, nil)
	s.testRead(c, d, data)
}

func (s *drbgSuite) testGenerate(c *C, d *DRBG, data *testData) {
	r := make([]byte, len(data.expected))
	c.Check(d.Generate(data.additionalInput[0], r), IsNil)

	c.Check(d.Generate(data.additionalInput[1], r), IsNil)
	c.Check(r, DeepEquals, data.expected)
}

func (s *drbgSuite) testGenerateAfterReseed(c *C, d *DRBG, data *testData) {
	d.ReseedWithExternalEntropy(data.entropyInputReseed, data.additionalInputReseed)
	s.testGenerate(c, d, data)
}

func (s *drbgSuite) testHash(c *C, h crypto.Hash, data *testData) {
	d := s.newHash(c, h, data)
	s.testRead(c, d, data)
}

func (s *drbgSuite) testHashGenerate(c *C, h crypto.Hash, data *testData) {
	d := s.newHash(c, h, data)
	s.testGenerate(c, d, data)
}

func (s *drbgSuite) testHashAfterReseed(c *C, h crypto.Hash, data *testData) {
	d := s.newHash(c, h, data)
	s.testReadAfterReseed(c, d, data)
}

func (s *drbgSuite) testHashGenerateAfterReseed(c *C, h crypto.Hash, data *testData) {
	d := s.newHash(c, h, data)
	s.testGenerateAfterReseed(c, d, data)
}

func (s *drbgSuite) testHMAC(c *C, h crypto.Hash, data *testData) {
	d := s.newHMAC(c, h, data)
	s.testRead(c, d, data)
}

func (s *drbgSuite) testHMACGenerate(c *C, h crypto.Hash, data *testData) {
	d := s.newHMAC(c, h, data)
	s.testGenerate(c, d, data)
}

func (s *drbgSuite) testHMACAfterReseed(c *C, h crypto.Hash, data *testData) {
	d := s.newHMAC(c, h, data)
	s.testReadAfterReseed(c, d, data)
}

func (s *drbgSuite) testHMACGenerateAfterReseed(c *C, h crypto.Hash, data *testData) {
	d := s.newHMAC(c, h, data)
	s.testGenerateAfterReseed(c, d, data)
}

func (s *drbgSuite) testCTR(c *C, keyLen int, data *testData) {
	d := s.newCTR(c, keyLen, data)
	s.testRead(c, d, data)
}

func (s *drbgSuite) testCTRGenerate(c *C, keyLen int, data *testData) {
	d := s.newCTR(c, keyLen, data)
	s.testGenerate(c, d, data)
}

func (s *drbgSuite) testCTRAfterReseed(c *C, keyLen int, data *testData) {
	d := s.newCTR(c, keyLen, data)
	s.testReadAfterReseed(c, d, data)
}

func (s *drbgSuite) testCTRGenerateAfterReseed(c *C, keyLen int, data *testData) {
	d := s.newCTR(c, keyLen, data)
	s.testGenerateAfterReseed(c, d, data)
}

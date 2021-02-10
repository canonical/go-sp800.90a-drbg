// Copyright 2021 Canonical Ltd.

// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"unicode"
)

type cipherData struct {
	cipher string
	keyLenBytes string
	keyLenBits string
}

var (
	hashes = map[string]string{
		"SHA-1": "SHA1",
		"SHA-224": "SHA224",
		"SHA-256": "SHA256",
		"SHA-384": "SHA384",
		"SHA-512": "SHA512",
		"SHA-512/224": "SHA512_224",
		"SHA-512/256": "SHA512_256",
	}

	ciphers = map[string]cipherData{
		"AES-128 use df": {"AES", "16", "128"},
		"AES-192 use df": {"AES", "24", "192"},
		"AES-256 use df": {"AES", "32", "256"},
	}
)

func scanTokens(data []byte, atEOF bool) (int, []byte, error) {
	// Scan until the end of the line
	lineAdv, tok, err := bufio.ScanLines(data, atEOF)
	switch {
	case err != nil:
		return 0, nil, err
	case lineAdv == 0:
		// Request a new line
		return 0, nil, nil
	case len(tok) == 0:
		// Return a newline as a token
		return lineAdv, []byte{'\n'}, nil
	}

	// Skip space
	adv := strings.IndexFunc(string(tok), func(r rune) bool {
		return !unicode.IsSpace(r)
	})
	if adv < 0 {
		// The rest of the line is all space - request a new one
		return lineAdv, []byte{'\n'}, nil
	}
	tok = tok[adv:]

	// The rest of the line is a comment - request a new one
	if tok[0] == '#' {
		return lineAdv, []byte{'\n'}, nil
	}

	// Find the next delimiter
	i := strings.IndexAny(string(tok), "[]=")
	switch {
	case i == 0:
		tok = []byte{tok[0]}
	case i >= 0:
		tok = tok[:i]
	}

	tok = []byte(strings.TrimSpace(string(tok)))

	return adv + len(tok), tok, nil
}

type testCase map[string]string

type testSuite struct {
	name string
	params map[string]string
	tests []testCase
}

type stateFunc func(string) (stateFunc, error)

type parser struct {
	scanner *bufio.Scanner
	current stateFunc

	suites []*testSuite
	currentSuite *testSuite
	currentTest testCase
	currentName string
}

func (p *parser) handleEndTestCaseParam(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return p.handleStartTestCaseParam, nil
	default:
		return nil, fmt.Errorf("handleEndTestCaseParam: unexpected token %v", tok)
	}
}

func (p *parser) handleTestCaseParam(tok string) (stateFunc, error) {
	p.currentTest[p.currentName] = tok
	return p.handleEndTestCaseParam, nil
}

func (p *parser) handleEndTestSuiteParam2(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return p.handleStartTestSuiteParam, nil
	default:
		return nil, fmt.Errorf("handleEndTestSuiteParam2: unexpected token %v", tok)
	}
}

func (p *parser) handleEndTestSuiteParam(tok string) (stateFunc, error) {
	switch {
	case tok == "]":
		return p.handleEndTestSuiteParam2, nil
	default:
		return nil, fmt.Errorf("handleEndTestSuiteParam: unexpected token %v", tok)
	}
}

func (p *parser) handleEndTestSuiteName(tok string) (stateFunc, error) {
	switch {
	case tok == "]":
		p.currentSuite.name = p.currentName
		return p.handleEndTestSuiteParam(tok)
	case tok == "=":
		return p.handleEqual(tok)
	default:
		return nil, fmt.Errorf("handleEndTestSuiteName: unexpected token %v", tok)
	}
}

func (p *parser) handleTestSuiteParam(tok string) (stateFunc, error) {
	if p.currentSuite.name == "" {
		p.currentSuite.name = tok
	}
	p.currentSuite.params[p.currentName] = tok
	return p.handleEndTestSuiteParam, nil
}

func (p *parser) handleParamValue(tok string) (stateFunc, error) {
	switch {
	case tok == "[" || tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleParamValue: unexpected token %v", tok)
	case tok == "\n" && p.currentTest != nil:
		return p.handleStartTestCaseParam, nil
	case tok == "\n":
		return nil, fmt.Errorf("handleParamValue: unexpected token %v", tok)
	case p.currentTest != nil:
		return p.handleTestCaseParam(tok)
	default:
		return p.handleTestSuiteParam(tok)
	}
}

func (p *parser) handleEqual(tok string) (stateFunc, error) {
	switch {
	case tok == "=":
		return p.handleParamValue, nil
	default:
		return nil, fmt.Errorf("handleEqual: unexpected token %v", tok)
	}
}

func (p *parser) handleParamName(tok string) (stateFunc, error) {
	switch {
	case tok == "\n" || tok == "[" || tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleParamName: unexpected token %v", tok)
	default:
		p.currentName = string(tok)
		return p.handleEqual, nil
	}
}

func (p *parser) handleStartTestCaseParam(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		p.currentSuite.tests = append(p.currentSuite.tests, p.currentTest)
		p.currentTest = nil
		return p.start, nil
	case tok == "[" || tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleStartTestCaseParam: unexpected token %v", tok)
	default:
		return p.handleParamName(tok)
	}
}

func (p *parser) handleStartTestSuiteParam2(tok string) (stateFunc, error) {
	switch {
	case tok == "[" || tok == "]" || tok == "=" || tok == "\n":
		return nil, fmt.Errorf("handleStartTestSuiteParam2: unexpected token %v", tok)
	default:
		return p.handleParamName(tok)
	}
}

func (p *parser) handleStartTestSuiteParam(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return p.start, nil
	case tok == "[":
		return p.handleStartTestSuiteParam2, nil
	case tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleStartTestSuiteParam: unexpected token %v", tok)
	default:
		p.currentTest = make(testCase)
		return p.handleStartTestCaseParam(tok)
	}
}

func (p *parser) handleStartTestSuiteName2(tok string) (stateFunc, error) {
	switch {
	case tok == "[" || tok == "]" || tok == "=" || tok == "\n":
		return nil, fmt.Errorf("handleStartTestSuiteName2: unexpected token %v", tok)
	default:
		p.currentName = tok
		return p.handleEndTestSuiteName, nil
	}
}

func (p *parser) handleStartTestSuiteName(tok string) (stateFunc, error) {
	switch {
	case tok == "[":
		return p.handleStartTestSuiteName2, nil
	default:
		return nil, fmt.Errorf("handleStartTestSuiteName: unexpected token %v", tok)
	}
}

func (p *parser) start(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return nil, nil
	case tok == "[":
		p.currentSuite = &testSuite{params: make(map[string]string)}
		p.suites = append(p.suites, p.currentSuite)
		return p.handleStartTestSuiteName(tok)
	case tok == "]" || tok == "=":
		return nil, fmt.Errorf("start: unexpected token %v", tok)
	default:
		if p.currentSuite == nil {
			return nil, fmt.Errorf("start: unexpected token %v (no current suite)", tok)
		}
		p.currentTest = make(testCase)
		return p.handleStartTestCaseParam(tok)
	}
}

func (p *parser) run() error {
	for p.scanner.Scan() {
		next, err := p.current(p.scanner.Text())
		if err != nil {
			return err
		}
		if next != nil {
			p.current = next
		}
	}
	return nil
}

func newParser(r io.Reader) *parser {
	scanner := bufio.NewScanner(r)
	scanner.Split(scanTokens)
	p := &parser{scanner: scanner}
	p.current = p.start
	return p
}

var errSkipSuite = errors.New("")

func generateTests(vectors string, filter map[string]string, emitSuite func(*testSuite, int) error, emitTest func(*testSuite, int, int, testCase) error) error {
	f, err := os.Open(vectors)
	if err != nil {
		return err
	}
	defer f.Close()

	parser := newParser(f)
	if err := parser.run(); err != nil {
		return err
	}

	for i, suite := range parser.suites {
		skip := false
		for k, v := range filter {
			if suite.params[k] != v {
				skip = true
				break
			}
		}

		if skip {
			continue
		}

		if err := emitSuite(suite, i); err != nil {
			if err == errSkipSuite {
				continue
			}
			return err
		}

		for j, test := range suite.tests {
			if err := emitTest(suite, i, j, test); err != nil {
				return err
			}
		}
	}

	return nil
}

type atomicFile struct {
	*os.File
	path string
}

func (f *atomicFile) Commit() error {
	return os.Rename(f.Name(), f.path)
}

func (f *atomicFile) Close() error {
	os.Remove(f.Name())
	return f.File.Close()
}

func newAtomicFile(path string) (*atomicFile, error) {
	f, err := ioutil.TempFile("", "gentest")
	if err != nil {
		return nil, fmt.Errorf("cannot create temporary file: %v", err)
	}
	return &atomicFile{f, path}, nil
}


func generateHashTests() error {
	tmpl, err := os.Open("testdata/hash_test.go.in")
	if err != nil {
		return err
	}
	defer tmpl.Close()

	f, err := newAtomicFile("hash_test.go")
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, tmpl); err != nil {
		return fmt.Errorf("cannot copy template: %v", err)
	}

	if err := generateTests("testdata/no_reseed/Hash_DRBG.rsp", map[string]string{"AdditionalInputLen":"0"},
		func (suite *testSuite, i int) error {
			h, ok := hashes[suite.name]
			if !ok {
				return errSkipSuite
			}
			suite.params["HASH"] = h
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) testHash%[1]d_%[2]s(c *C, data *testData) {
	s.testHash(c, crypto.%[2]s, data)
}`,
			i, h)
			return err
		},
		func (suite *testSuite, i, j int, test testCase) error {
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) TestHash%[1]d_%[2]s_%[3]d(c *C) {
	s.testHash%[1]d_%[2]s(c, &testData{
		entropyInput: decodeHexString(c, "%[4]s"),
		nonce: decodeHexString(c, "%[5]s"),
		personalization: decodeHexString(c, "%[6]s"),
		expected: decodeHexString(c, "%[7]s"),
	})
}`,
			i, suite.params["HASH"], j, test["EntropyInput"], test["Nonce"], test["PersonalizationString"], test["ReturnedBits"])
			return err
		},
	); err != nil {
		return err
	}

	if err := generateTests("testdata/pr_false/Hash_DRBG.rsp", map[string]string{"AdditionalInputLen":"0"},
		func (suite *testSuite, i int) error {
			h, ok := hashes[suite.name]
			if !ok {
				return errSkipSuite
			}
			suite.params["HASH"] = h
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) testHashAfterReseed%[1]d_%[2]s(c *C, data *testData) {
	s.testHashAfterReseed(c, crypto.%[2]s, data)
}`,
			i, h)
			return err
		},
		func (suite *testSuite, i, j int, test testCase) error {
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) TestHashAfterReseed%[1]d_%[2]s_%[3]d(c *C) {
	s.testHashAfterReseed%[1]d_%[2]s(c, &testData{
		entropyInput: decodeHexString(c, "%[4]s"),
		nonce: decodeHexString(c, "%[5]s"),
		personalization: decodeHexString(c, "%[6]s"),
		entropyInputReseed: decodeHexString(c, "%[7]s"),
		expected: decodeHexString(c, "%[8]s"),
	})
}`,
			i, suite.params["HASH"], j, test["EntropyInput"], test["Nonce"], test["PersonalizationString"], test["EntropyInputReseed"], test["ReturnedBits"])
			return err
		},
	); err != nil {
		return err
	}

	if err := f.Commit(); err != nil {
		return fmt.Errorf("cannot commit file: %v", err)
	}
	return nil
}

func generateHMACTests() error {
	tmpl, err := os.Open("testdata/hmac_test.go.in")
	if err != nil {
		return err
	}
	defer tmpl.Close()

	f, err := newAtomicFile("hmac_test.go")
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, tmpl); err != nil {
		return fmt.Errorf("cannot copy template: %v", err)
	}

	if err := generateTests("testdata/no_reseed/HMAC_DRBG.rsp", map[string]string{"AdditionalInputLen":"0"},
		func (suite *testSuite, i int) error {
			h, ok := hashes[suite.name]
			if !ok {
				return errSkipSuite
			}
			suite.params["HASH"] = h
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) testHMAC%[1]d_%[2]s(c *C, data *testData) {
	s.testHMAC(c, crypto.%[2]s, data)
}`,
			i, h)
			return err
		},
		func (suite *testSuite, i, j int, test testCase) error {
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) TestHMAC%[1]d_%[2]s_%[3]d(c *C) {
	s.testHMAC%[1]d_%[2]s(c, &testData{
		entropyInput: decodeHexString(c, "%[4]s"),
		nonce: decodeHexString(c, "%[5]s"),
		personalization: decodeHexString(c, "%[6]s"),
		expected: decodeHexString(c, "%[7]s"),
	})
}`,
			i, suite.params["HASH"], j, test["EntropyInput"], test["Nonce"], test["PersonalizationString"], test["ReturnedBits"])
			return err
		},
	); err != nil {
		return err
	}

	if err := generateTests("testdata/pr_false/HMAC_DRBG.rsp", map[string]string{"AdditionalInputLen":"0"},
		func (suite *testSuite, i int) error {
			h, ok := hashes[suite.name]
			if !ok {
				return errSkipSuite
			}
			suite.params["HASH"] = h
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) testHMACAfterReseed%[1]d_%[2]s(c *C, data *testData) {
	s.testHMACAfterReseed(c, crypto.%[2]s, data)
}`,
			i, h)
			return err
		},
		func (suite *testSuite, i, j int, test testCase) error {
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) TestHMACAfterReseed%[1]d_%[2]s_%[3]d(c *C) {
	s.testHMACAfterReseed%[1]d_%[2]s(c, &testData{
		entropyInput: decodeHexString(c, "%[4]s"),
		nonce: decodeHexString(c, "%[5]s"),
		personalization: decodeHexString(c, "%[6]s"),
		entropyInputReseed: decodeHexString(c, "%[7]s"),
		expected: decodeHexString(c, "%[8]s"),
	})
}`,
			i, suite.params["HASH"], j, test["EntropyInput"], test["Nonce"], test["PersonalizationString"], test["EntropyInputReseed"], test["ReturnedBits"])
			return err
		},
	); err != nil {
		return err
	}

	if err := f.Commit(); err != nil {
		return fmt.Errorf("cannot commit file: %v", err)
	}
	return nil
}

func generateCTRTests() error {
	tmpl, err := os.Open("testdata/ctr_test.go.in")
	if err != nil {
		return err
	}
	defer tmpl.Close()

	f, err := newAtomicFile("ctr_test.go")
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, tmpl); err != nil {
		return fmt.Errorf("cannot copy template: %v", err)
	}

	if err := generateTests("testdata/no_reseed/CTR_DRBG.rsp", map[string]string{"AdditionalInputLen":"0"},
		func (suite *testSuite, i int) error {
			c, ok := ciphers[suite.name]
			if !ok {
				return errSkipSuite
			}
			suite.params["KEYLEN"] = c.keyLenBits
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) testCTR%[1]d_AES%[2]s(c *C, data *testData) {
	s.testCTR(c, %[3]s, data)
}`,
			i, c.keyLenBits, c.keyLenBytes)
			return err
		},
		func (suite *testSuite, i, j int, test testCase) error {
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) TestCTR%[1]d_AES%[2]s_%[3]d(c *C) {
	s.testCTR%[1]d_AES%[2]s(c, &testData{
		entropyInput: decodeHexString(c, "%[4]s"),
		nonce: decodeHexString(c, "%[5]s"),
		personalization: decodeHexString(c, "%[6]s"),
		expected: decodeHexString(c, "%[7]s"),
	})
}`,
			i, suite.params["KEYLEN"], j, test["EntropyInput"], test["Nonce"], test["PersonalizationString"], test["ReturnedBits"])
			return err
		},
	); err != nil {
		return err
	}

	if err := generateTests("testdata/pr_false/CTR_DRBG.rsp", map[string]string{"AdditionalInputLen":"0"},
		func (suite *testSuite, i int) error {
			c, ok := ciphers[suite.name]
			if !ok {
				return errSkipSuite
			}
			suite.params["KEYLEN"] = c.keyLenBits
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) testCTRAfterReseed%[1]d_AES%[2]s(c *C, data *testData) {
	s.testCTRAfterReseed(c, %[3]s, data)
}`,
			i, c.keyLenBits, c.keyLenBytes)
			return err
		},
		func (suite *testSuite, i, j int, test testCase) error {
			_, err := fmt.Fprintf(f, `

func (s *drbgSuite) TestCTRAfterReseed%[1]d_AES%[2]s_%[3]d(c *C) {
	s.testCTRAfterReseed%[1]d_AES%[2]s(c, &testData{
		entropyInput: decodeHexString(c, "%[4]s"),
		nonce: decodeHexString(c, "%[5]s"),
		personalization: decodeHexString(c, "%[6]s"),
		entropyInputReseed: decodeHexString(c, "%[7]s"),
		expected: decodeHexString(c, "%[8]s"),
	})
}`,
			i, suite.params["KEYLEN"], j, test["EntropyInput"], test["Nonce"], test["PersonalizationString"], test["EntropyInputReseed"], test["ReturnedBits"])
			return err
		},
	); err != nil {
		return err
	}

	if err := f.Commit(); err != nil {
		return fmt.Errorf("cannot commit file: %v", err)
	}
	return nil
}

func run() error {
	if err := generateHashTests(); err != nil {
		return fmt.Errorf("cannot generate hash tests: %v", err)
	}
	if err := generateHMACTests(); err != nil {
		return fmt.Errorf("cannot generate HMAC tests: %v", err)
	}
	if err := generateCTRTests(); err != nil {
		return fmt.Errorf("cannot generate CTR tests: %v", err)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

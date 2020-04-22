// Copyright (c) 2020 Emanuele Bellocchia
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//
// This file cointains entropy generation functions for bip39 package.
//

package bip39

//
// Imports
//
import (
	"crypto/rand"
	"errors"
)

//
// Constants
//
const (
	// Entropy bit lengths
	EntropyBits128 = 128
	EntropyBits160 = 160
	EntropyBits192 = 192
	EntropyBits224 = 224
	EntropyBits256 = 256
)

//
// Variables
//
var (
	// ErrEntropyBitLen is returned when trying to generate entropy with invalid bit length
	ErrEntropyBitLen = errors.New("The specified bit length is not valid for entropy generation")

	// Helper map for checking bit length validity
	entropyBitLenMap = map[int]bool {
		EntropyBits128 : true,
		EntropyBits160 : true,
		EntropyBits192 : true,
		EntropyBits224 : true,
		EntropyBits256 : true,
	}
)

//
// Exported functions
//

// Generate entropy bytes with the specified bit length.
func GenerateEntropy(bitLen int) ([]byte, error) {
	// Validate bit length
	err := validateEntropyBitLen(bitLen)
	if err != nil {
		return nil, err
	}

	// Generate random entropy
	entropy := make([]byte, bitLen / 8)
	_, err = rand.Read(entropy)
	return entropy, err
}

//
// Not-exported functions
//

// Validate the specified bit length.
func validateEntropyBitLen(bitLen int) error {
	if !entropyBitLenMap[bitLen] {
		return ErrEntropyBitLen
	}
	return nil
}

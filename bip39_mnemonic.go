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
// This file cointains mnemonic generation/validation for bip39 package.
//

package bip39

//
// Imports
//
import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"golang.org/x/crypto/pbkdf2"
)

//
// Constants
//
const (
	// Words number
	WordsNum12 = 12
	WordsNum15 = 15
	WordsNum18 = 18
	WordsNum21 = 21
	WordsNum24 = 24

	// Word bit length
	wordBitLen = 11

	// Modified for seed salt
	seedSaltMod = "mnemonic"
	// Key length for PBKDF2 algorithm
	seedPbkdf2KeyLen = 64
	// Number of round for PBKDF2 algorithm
	seedPbkdf2Round = 2048
)

//
// Variables
//
var (
	// ErrWordsNum is returned when trying to generate mnemonic with invalid words number
	ErrWordsNum = errors.New("The specified words number is not valid for mnemonic generation")
	// ErrInvalidWord is returned when trying to get entropy or validating a mnemonic with invalid words
	ErrInvalidWord = errors.New("The mnemonic contains an invalid word")
	// ErrChecksum is returned when trying to get entropy or validating a mnemonic with invalid checksum
	ErrChecksum = errors.New("The checksum of the mnemonic is not valid")

	// Helper map for checking words number validity
	wordsNumMap = map[int]bool {
		WordsNum12 : true,
		WordsNum15 : true,
		WordsNum18 : true,
		WordsNum21 : true,
		WordsNum24 : true,
	}
)

//
// Types
//

// Structure for mnemonic
type Mnemonic struct {
	Words string
}

//
// Exported functions
//

// Generate mnemonic from the specified words number.
// A random entropy is used for generating mnemonic.
func MnemonicFromWordsNum(wordsNum int) (*Mnemonic, error) {
	// Validate words number
	err := validateWordsNum(wordsNum)
	if err != nil {
		return nil, err
	}

	// Get entropy bit length from words number
	entropyBitLen := (wordsNum * 11) - (wordsNum / 3)
	// Generate entropy
	entropy, _ := GenerateEntropy(entropyBitLen)

	// Generate mnemonic from entropy
	return MnemonicFromEntropy(entropy)
}

// Generate mnemonic from the specific entropy.
// The entropy slice shall be of a valid length.
func MnemonicFromEntropy(entropy []byte) (*Mnemonic, error) {
	// Validate entropy bit length
	err := validateEntropyBitLen(len(entropy) * 8)
	if err != nil {
		return nil, err
	}

	// Convert entropy to binary string
	entropyBinStr := bytesToBinaryString(entropy)
	// Compute checksum as binary string
	chksumBinStr := entropyChecksumBinStr(entropy)
	// Append it to entropy
	mnemonicBinStr := entropyBinStr + chksumBinStr

	// Create slice for mnemonic
	mnemonicLen := len(mnemonicBinStr) / wordBitLen
	mnemonic := make([]string, 0, mnemonicLen)

	// Split binary string in groups of 11-bit and map them to the words list
	for i := 0; i < mnemonicLen; i++ {
		// Get current word binary string
		wordStrBin := mnemonicBinStr[i * wordBitLen: (i + 1) * wordBitLen]
		// Convert to integer
		wordIdx, _ := strconv.ParseInt(wordStrBin, 2, 16)
		// Append the correspondent word
		mnemonic = append(mnemonic, wordsListEn[wordIdx])
	}

	return &Mnemonic {
		Words: strings.Join(mnemonic, " "),
	}, nil
}

// Create mnemonic object from a mnemonic string.
func MnemonicFromString(mnemonic string) (*Mnemonic) {
	return &Mnemonic {
		Words: mnemonic,
	}
}

// Convert a mnemonic back to entropy bytes.
// Error is returned if mnemonic or checksum is not valid.
func (mnemonic *Mnemonic) ToEntropy() ([]byte, error) {
	// Get binary strings from mnemonic
	entropyBinStr, chksumBinStr, err := mnemonic.getBinaryStrings()
	if err != nil {
		return nil, err
	}

	// Get entropy bytes
	entropy, _ := binaryStringToBytes(entropyBinStr)
	// Compute checksum
	chksumComp := entropyChecksumBinStr(entropy)

	// Compare checksum
	if chksumComp != chksumBinStr {
		return nil, ErrChecksum
	}

	return entropy, nil
}

// Validate a mnemonic.
// For being valid, all the mnemonic words shall exists in the words list and the checksum shall be valid.
func (mnemonic *Mnemonic) Validate() error {
	// Get binary strings from mnemonic
	entropyBinStr, chksumBinStr, err := mnemonic.getBinaryStrings()
	if err != nil {
		return err
	}

	// Get entropy bytes
	entropy, _ := binaryStringToBytes(entropyBinStr)
	// Compute checksum
	chksumComp := entropyChecksumBinStr(entropy)

	// Compare checksum
	if chksumComp != chksumBinStr {
		return ErrChecksum
	}

	return nil

}

// Get if a mnemonic is valid.
// It's the same of the Validate method but returns bool instead of error.
func (mnemonic *Mnemonic) IsValid() bool {
	return mnemonic.Validate() == nil
}

// Generate the seed from a mnemonic using the specified passphrase for protection.
func (mnemonic *Mnemonic) GenerateSeed(passphrase string) ([]byte, error) {
	// Validate mnemonic
	err := mnemonic.Validate()
	if err != nil {
		return nil, err
	}

	// Get salt
	salt := seedSaltMod + passphrase
	// Generate seed
	return pbkdf2.Key([]byte(mnemonic.Words), []byte(salt), seedPbkdf2Round, seedPbkdf2KeyLen, sha512.New), nil
}

//
// Not-exported functions
//

// Validate the specified words number.
func validateWordsNum(wordsNum int) error {
	if !wordsNumMap[wordsNum] {
		return ErrWordsNum
	}
	return nil
}

// Compute checksum of the specified entropy bytes, returned as a binary string.
func entropyChecksumBinStr(slice []byte) string {
	// Compute SHA256
	hash := sha256.Sum256(slice)
	// Convert to binary string
	hashStr := bytesToBinaryString(hash[:])
	// Get checksum length in bits
	chksumBitLen := len(slice) / 4

	return hashStr[:chksumBitLen]
}

// Get the binary strings back from a mnemonic.
// The function returns both entropy and checksum parts.
func (mnemonic *Mnemonic) getBinaryStrings() (string, string, error) {
	// Get word list
	wordsList := strings.Split(mnemonic.Words, " ")
	// Validate words number
	err := validateWordsNum(len(wordsList))
	if err != nil {
		return "", "", err
	}

	// Build the binary string by converting each word index
	var strBuf bytes.Buffer
	for _, word := range wordsList {
		// Use binary search for getting the word index
		wordIdx := stringBinarySearch(wordsListEn, word)
		// Error if not found
		if wordIdx == -1 {
			return "", "", ErrInvalidWord
		}
		// Convert the index to 11-bit binary string
		strBuf.WriteString(fmt.Sprintf("%.11b", wordIdx))
	}

	// Get mnemonic binary string
	mnemonicBinStr := strBuf.String()
	// Compute checksum length and index
	chksumLen := len(mnemonicBinStr) / 33
	chksumIdx := len(mnemonicBinStr) - chksumLen

	// Split mnemonic
	return mnemonicBinStr[:chksumIdx], mnemonicBinStr[chksumIdx:], nil
}

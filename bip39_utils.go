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
// This file cointains some utility functions for bip39 package.
//

package bip39

//
// Imports
//
import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

//
// Variables
//
var (
	// ErrBinaryString is returned when trying to convert an invalid binary string to byte slice
	ErrBinaryString = errors.New("The specified binary string is not valid")
)

//
// Not-exported functions
//

// Convert the specified byte slice to a binary string.
func bytesToBinaryString(slice []byte) string {
	// Convert each byte to its bits representation as string
	var strBuff bytes.Buffer
	for _, b := range(slice) {
		strBuff.WriteString(fmt.Sprintf("%.8b", b))
	}

	return strBuff.String()
}

// Convert the specified binary string to a byte slice.
func binaryStringToBytes(binStr string) ([]byte, error) {
	// Length of the binary string shall be multiple of 8
	if (len(binStr) % 8) != 0 {
		return nil, ErrBinaryString
	}

	// Create slice
	slice := make([]byte, 0, len(binStr) / 8)

	// Split the string into groups of 8-bit and convert each of them to byte
	for i := 0; i < len(binStr); i += 8 {
		// Convert current byte
		byteStrBin := binStr[i: i + 8]
		byteVal, err := strconv.ParseInt(byteStrBin, 2, 16)
		// Stop if conversion error
		if err != nil {
			return nil, err
		}
		// Append new byte
		slice = append(slice, byte(byteVal))
	}

	return slice, nil
}

// Perform binary search to find a string in a slice, by returning its index.
// If not found, -1 will be returned.
// The algorithm is simply implemented by using the sort library.
func stringBinarySearch(slice []string, elem string) int {
	idx := sort.SearchStrings(slice, elem)

	if idx != len(slice) && slice[idx] == elem {
		return idx
	} else {
		return -1
	}
}

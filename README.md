# Bip39 package
[![Build Status](https://travis-ci.com/ebellocchia/go-bip39.svg?branch=master)](https://travis-ci.com/ebellocchia/go-bip39)
[![codecov](https://codecov.io/gh/ebellocchia/go-bip39/branch/master/graph/badge.svg)](https://codecov.io/gh/ebellocchia/go-bip39)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/ebellocchia/go-bip39/master/LICENSE)

## Introduction

This package implements the [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) specification. This includes:
- Mnemonic generation from a specified number of words, using random entropy
- Mnemonic generation from a specified entropy
- Mnemonic validation
- Seed generation from a mnemonic with a specified passphrase

**NOTE:** only the English words list is currently supported.

## Installation

The package can be installed by simply running:

    go get -u github.com/ebellocchia/go-bip39

## Usage

The package is pretty easy to use, so a code example is probably self-explanatory.

**Example**

    package main

    import (
      "github.com/ebellocchia/go-bip39"
      "fmt"
      "encoding/hex"
    )

    func main() {
        // Generate a random entropy with the specified number of bits
        // An error is returned if the entropy bit length is not valid
        entropy, err := bip39.GenerateEntropy(bip39.EntropyBits128)
        if err != nil {
            panic(err)
        }
        fmt.Println(hex.EncodeToString(entropy))

        // Generate a mnemonic from the entropy
        // An error is returned if the entropy bit length is not valid
        mnemonic, err := bip39.MnemonicFromEntropy(entropy)
        if err != nil {
            panic(err)
        }
        fmt.Println(mnemonic.Words)

        // Generate a mnemonic with a specified number of words (a random entropy will be generated internally)
        // An error is returned if the number of words is not valid
        mnemonic, err = bip39.MnemonicFromWordsNum(bip39.WordsNum12)
        if err != nil {
            panic(err)
        }
        fmt.Println(mnemonic.Words)

        // Create a mnemonic directly from an existent string
        mnemonic = bip39.MnemonicFromString("legal winner thank year wave sausage worth useful legal winner thank yellow")
        fmt.Println(mnemonic.Words)

        // Get entropy back from the mnemonic
        // An error is returned if the mnemonic is not valid
        entropy, err = mnemonic.ToEntropy()
        if err != nil {
            panic(err)
        }
        fmt.Println(hex.EncodeToString(entropy))

        // Validate a mnemonic, return an error if not valid
        err = mnemonic.Validate()
        if err != nil {
            panic(err)
        }

        // Get if the mnemonic is valid. Same of before but bool is returned instead of error.
        is_valid := mnemonic.IsValid()
        if !is_valid {
            // Do something...
        }

        // Generate a seed from the mnemonic using the specified passphrase (can be also empty)
        // An error is returned if the mnemonic is not valid
        seed, err := mnemonic.GenerateSeed("my_passphrase")
        if err != nil {
            panic(err)
        }
        fmt.Println(hex.EncodeToString(seed))
    }

The valid bit lengths for entropy generation are:
- *bip39.EntropyBits128*
- *bip39.EntropyBits160*
- *bip39.EntropyBits192*
- *bip39.EntropyBits224*
- *bip39.EntropyBits256*

The valid words number for mnemonic generation are:
- *bip39.WordsNum12*
- *bip39.WordsNum15*
- *bip39.WordsNum18*
- *bip39.WordsNum21*
- *bip39.WordsNum24*

## License

This software is available under the MIT license.

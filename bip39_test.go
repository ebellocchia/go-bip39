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

package bip39

//
// Imports
//
import (
	"encoding/hex"
	"strings"
	"testing"
)

//
// Types
//

// Test vector entry structure
type testVectEntry struct {
	Entropy  string
	Mnemonic string
	Seed     string
}

// Invalid mnemonic test vector entry structure
type testVectInvalidMnemonicEntry struct {
	Mnemonic string
	Err      error
}

//
// Constants
//
const (
	// Passphrase for ssed generation
	testPassphrase = "TREZOR"
)

//
// Variables
//

// Tests from BIP-0039 page:
// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
var testVect = []testVectEntry {
    // Basic 12-words
    testVectEntry {
        Entropy:  "00000000000000000000000000000000",
        Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Seed:     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    },
    testVectEntry {
        Entropy:  "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        Mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
        Seed:     "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    },
    testVectEntry {
        Entropy:  "80808080808080808080808080808080",
        Mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        Seed:     "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    },
    testVectEntry {
        Entropy:  "ffffffffffffffffffffffffffffffff",
        Mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        Seed:     "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    },
    // Basic 18-words
    testVectEntry {
        Entropy:  "000000000000000000000000000000000000000000000000",
        Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        Seed:     "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
    },
    testVectEntry {
        Entropy:  "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        Mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        Seed:     "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
    },
    testVectEntry {
        Entropy:  "808080808080808080808080808080808080808080808080",
        Mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        Seed:     "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
    },
    testVectEntry {
        Entropy:  "ffffffffffffffffffffffffffffffffffffffffffffffff",
        Mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        Seed:     "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
    },
    // Basic 24-words
    testVectEntry {
        Entropy:  "0000000000000000000000000000000000000000000000000000000000000000",
        Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        Seed:     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    },
    testVectEntry {
        Entropy:  "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        Mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        Seed:     "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
    },
    testVectEntry {
        Entropy:  "8080808080808080808080808080808080808080808080808080808080808080",
        Mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        Seed:     "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
    },
    testVectEntry {
        Entropy:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        Mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        Seed:     "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
    },
    // Various
    testVectEntry {
        Entropy:  "9e885d952ad362caeb4efe34a8e91bd2",
        Mnemonic: "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        Seed:     "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
    },
    testVectEntry {
        Entropy:  "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        Mnemonic: "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        Seed:     "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
    },
    testVectEntry {
        Entropy:  "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        Mnemonic: "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        Seed:     "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
    },

    testVectEntry {
        Entropy:  "c0ba5a8e914111210f2bd131f3d5e08d",
        Mnemonic:  "scheme spot photo card baby mountain device kick cradle pact join borrow",
        Seed:     "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
    },
    testVectEntry {
        Entropy:  "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
        Mnemonic: "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
        Seed:     "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
    },
    testVectEntry {
        Entropy:  "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        Mnemonic: "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        Seed:     "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
    },

    testVectEntry {
        Entropy:  "23db8160a31d3e0dca3688ed941adbf3",
        Mnemonic:  "cat swing flag economy stadium alone churn speed unique patch report train",
        Seed:     "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
    },
    testVectEntry {
        Entropy:  "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
        Mnemonic: "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
        Seed:     "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
    },
    testVectEntry {
        Entropy:  "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        Mnemonic: "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        Seed:     "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
    },

    testVectEntry {
        Entropy:  "f30f8c1da665478f49b001d94c5fc452",
        Mnemonic:  "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        Seed:     "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
    },
    testVectEntry {
        Entropy:  "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
        Mnemonic: "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
        Seed:     "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
    },
    testVectEntry {
        Entropy:  "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        Mnemonic: "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        Seed:     "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
    },
}

// Test for valid words number
var testVectWordsNumValid = []int {
	WordsNum12,
	WordsNum15,
	WordsNum18,
	WordsNum21,
	WordsNum24,
}

// Test for invalid words number
var testVectWordsNumInvalid = []int {
	11,
	16,
	19,
	25,
}

// Test for valid entropy bit lengths
var testVectEntropyBitLenValid = []int {
	EntropyBits128,
	EntropyBits160,
	EntropyBits192,
	EntropyBits224,
	EntropyBits256,
}

// Test for invalid entropy bit lengths
var testVectEntropyBitLenInvalid = []int {
	127,
	129,
	159,
	161,
	191,
	193,
	223,
	225,
	255,
	257,
}

// Tests for invalid mnemonic
var testVectMnemonicInvalid = []testVectInvalidMnemonicEntry {
	// Invalid length
	testVectInvalidMnemonicEntry {
		Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
		Err:      ErrWordsNum,
	},
	// Invalid checksum
	testVectInvalidMnemonicEntry {
		Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon any",
		Err:      ErrChecksum,
	},
	// Not-existent word
	testVectInvalidMnemonicEntry {
		Mnemonic: "abandon abandon abandon notexistent abandon abandon abandon abandon abandon abandon abandon about",
		Err:      ErrInvalidWord,
	},
}

// Tests for invalid binary strings
var testBinaryStringInvalid = []string {
	// Invalid lengths
	"0000000",
	"000000010",
	"000000010000000",
	"00000001000000010",
	// Invalid formats
	"0000a001",
	"0000000100b00001",
}

//
// Functions
//

// Test vector
func TestVector(t *testing.T) {
	for _, currTest := range testVect {
		// Convert entropy to bytes
		entropy, _ := hex.DecodeString(currTest.Entropy)

		// Create mnemonic from entropy
		mnemonic, err := MnemonicFromEntropy(entropy)
		if err != nil {
			t.Errorf("Mnemonic from entropy %s returned error: %s", currTest.Entropy, err.Error())
		} else if mnemonic.Words != currTest.Mnemonic {
			t.Errorf("Mnemonic from entropy was incorrect: expected %s, got: %s", currTest.Mnemonic, mnemonic.Words)
		}

		// Validate mnemonic
		err = mnemonic.Validate()
		if err != nil {
			t.Errorf("Mnemonic '%s' validation returned error: %s", currTest.Mnemonic, err.Error())
		}

		// Check if mnemonic is valid
		is_valid := mnemonic.IsValid()
		if !is_valid {
			t.Errorf("Mnemonic '%s' is not valid", currTest.Mnemonic)
		}

		// Get entropy back from mnemonic
		got_entropy, err := mnemonic.ToEntropy()
		got_entropy_hex := hex.EncodeToString(got_entropy)
		if err != nil {
			t.Errorf("Mnemonic '%s' to entropy returned error: %s", currTest.Mnemonic, err.Error())
		} else if got_entropy_hex != currTest.Entropy {
			t.Errorf("Mnemonic '%s' to entropy was incorrect: expected %s, got: %s", currTest.Mnemonic, currTest.Entropy, got_entropy_hex)
		}

		// Generate seed from mnemonic
		seed, err := mnemonic.GenerateSeed(testPassphrase)
		seed_hex := hex.EncodeToString(seed)
		if err != nil {
			t.Errorf("Mnemonic '%s' seed generation returned error: %s", currTest.Mnemonic, err.Error())
		} else if seed_hex != currTest.Seed {
			t.Errorf("Mnemonic '%s' seed generation was incorrect: expected %s, got: %s", currTest.Mnemonic, currTest.Seed, seed_hex)
		}

		// Create mnemonic from string
		mnemonic = MnemonicFromString(currTest.Mnemonic)
		if mnemonic.Words != currTest.Mnemonic {
			t.Errorf("Mnemonic from string was incorrect: expected %s, got: %s", currTest.Mnemonic, mnemonic.Words)
		}
	}
}

// Test valid words number
func TestWordsNumValid(t *testing.T) {
	for _, testWordsNum := range testVectWordsNumValid {
		// Create mnemonic from words number
		mnemonic, err := MnemonicFromWordsNum(testWordsNum)
		// Check the number of words in the generated mnemonic
		gotWordsNum := len(strings.Split(mnemonic.Words, " "))
		if gotWordsNum != testWordsNum {
			t.Errorf("Mnemonic from valid words number was incorrect: expected %d, got: %d", testWordsNum, gotWordsNum)
		}
		if err != nil {
			t.Errorf("Mnemonic from valid words number (%d) returned error: %s", testWordsNum, err.Error())
		}
	}
}

// Test invalid words number
func TestWordsNumInvalid(t *testing.T) {
	for _, testWordsNum := range testVectWordsNumInvalid {
		// Create mnemonic from words number
		mnemonic, err := MnemonicFromWordsNum(testWordsNum)
		// Generated mnemonic shall be nil and error shall be not nil
		if mnemonic != nil {
			t.Errorf("Mnemonic from invalid words number (%d) was not nil", testWordsNum)
		}
		if err != ErrWordsNum {
			t.Errorf("Mnemonic from invalid words number (%d) returned wrong error (%s)", testWordsNum, err.Error())
		}
	}
}

// Test valid entropy bit lengths
func TestEntropyBitLenValid(t *testing.T) {
	for _, testBitLen := range testVectEntropyBitLenValid {
		// Generate entropy
		entropy, err := GenerateEntropy(testBitLen)
		gotBitLen := len(entropy) * 8
		// Check the length of the generated entropy
		if gotBitLen != testBitLen {
			t.Errorf("Entropy from valid bit length was incorrect: expected %d, got: %d", testBitLen, gotBitLen)
		}
		if err != nil {
			t.Errorf("Entropy from valid bit length (%d) returned error: %s", testBitLen, err.Error())
		}
	}
}

// Test invalid entropy bit lengths
func TestEntropyBitLenInvalid(t *testing.T) {
	for _, testBitLen := range testVectEntropyBitLenInvalid {
		// Generate entropy
		entropy, err := GenerateEntropy(testBitLen)
		// Generated entropy shall be nil and error shall be not nil
		if entropy != nil {
			t.Errorf("Entropy from invalid bit length (%d) was not nil", testBitLen)
		}
		if err != ErrEntropyBitLen {
			t.Errorf("Entropy from invalid bit length (%d) returned wrong error (%s)", testBitLen, err.Error())
		}

		// Construct a dummy entropy slice with invalid length
		// Subtract 8 because, otherwise, dividing by 8 could result in a correct byte length
		entropy = make([]byte, 0, (testBitLen - 8) / 8)
		// Do the same test for creating a mnemonic from entropy
		mnemonic, err := MnemonicFromEntropy(entropy)
		// Generated mnemonic shall be nil and error shall be not nil
		if mnemonic != nil {
			t.Errorf("Mnemonic from invalid entropy bit length (%d) was not nil", testBitLen)
		}
		if err != ErrEntropyBitLen {
			t.Errorf("Mnemonic from invalid entropy bit length (%d) returned wrong error (%s)", testBitLen, err.Error())
		}
	}
}

// Test invalid mnemonics
func TestMnemonicInvalid(t *testing.T) {
	for _, testEntry := range testVectMnemonicInvalid {
		// Create mnemonic from string
		mnemonic := MnemonicFromString(testEntry.Mnemonic)
		// Validate mnemonic, shall return error
		err := mnemonic.Validate()
		if err != testEntry.Err {
			t.Errorf("Invalid mnemonic '%s' validation returned wrong error (%s)", testEntry.Mnemonic, err.Error())
		}

		// Get entropy back from mnemonic
		entropy, err := mnemonic.ToEntropy()
		// Generated entropy shall be nil and error shall be not nil
		if entropy != nil {
			t.Errorf("Entropy from invalid mnemonic (%s) was not nil", testEntry.Mnemonic)
		}
		if err != testEntry.Err {
			t.Errorf("Entropy from invalid mnemonic (%s) returned wrong error (%s)", testEntry.Mnemonic, err.Error())
		}

		// Generate seed from mnemonic
		seed, err := mnemonic.GenerateSeed(testPassphrase)
		// Generated seed shall be nil and error shall be not nil
		if seed != nil {
			t.Errorf("Seed from invalid mnemonic (%s) was not nil", testEntry.Mnemonic)
		}
		if err != testEntry.Err {
			t.Errorf("Seed from invalid mnemonic (%s) returned wrong error (%s)", testEntry.Mnemonic, err.Error())
		}
	}
}

// Test invalid binary strings
// Valid strings are implicitly tested in the test vector
func TestBinaryStringInvalid(t *testing.T) {
	for _, testBinStr := range testBinaryStringInvalid {
		// Convert binary string to bytes
		slice, err := binaryStringToBytes(testBinStr)
		// Byte slice shall be nil and error shall be not nil
		if slice != nil {
			t.Errorf("Invalid binary string (%s) conversion byte slice was not nil", testBinStr)
		}
		if err == nil {
			t.Errorf("Invalid binary string (%s) conversion returned no error", testBinStr)
		}
	}
}

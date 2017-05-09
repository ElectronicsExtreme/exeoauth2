package encrypt

import (
	"crypto/sha512"
)

func EncryptText1Way(raw []byte, salt []byte) []byte {
	encrypted := sha512.Sum512(append(salt[:], raw...))
	return encrypted[:]
}

func EncryptText2Way() {

}

package encrypt

import (
	"crypto/rand"
	"crypto/sha512"
)

func EncryptText1Way(raw []byte, salt []byte) []byte {
	encrypted := sha512.Sum512(append(salt[:], raw...))
	return encrypted[:]
}

func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

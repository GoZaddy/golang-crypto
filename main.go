package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
)

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)


//hash
//encrypt
//decrypt
//public-key cryptography
//digital signing and verification - hmac

// pkcs7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}

	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		fmt.Println("here", n)
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			fmt.Println("hereeee")
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}


//encrypt encrypts a plaintext
func encrypt(key, plaintext string) (string, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return "", err
	}

	fmt.Println(len(plaintext))

	ptbs, _ := pkcs7Pad([]byte(plaintext), block.BlockSize())

	if len(ptbs)%aes.BlockSize != 0 {
		return "",errors.New("plaintext is not a multiple of the block size")
	}
	fmt.Println(len(ptbs))
	fmt.Println("Padded plaintext: ",ptbs)

	ciphertext := make([]byte, len(ptbs))
	var iv []byte = make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, ptbs)

	return hex.EncodeToString(iv) + ":" + hex.EncodeToString(ciphertext), nil
}


//decrypt decrypts ciphertext
func decrypt(key, ciphertext string) (string, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return "", err
	}

	ciphertextParts := strings.Split(ciphertext, ":")
	iv, err := hex.DecodeString(ciphertextParts[0])
	if err != nil {
		return "", err
	}
	ciphertextbs, err := hex.DecodeString(ciphertextParts[1])
	if err != nil {
		return "", err
	}

	if len(ciphertextParts[1]) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	// CBC mode always works in whole blocks.
	if len(ciphertextParts[1])%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)


	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertextbs, ciphertextbs)

	ciphertextbs, err = pkcs7Unpad(ciphertextbs, aes.BlockSize)
	if err != nil{
		return "", err
	}

	return string(ciphertextbs), nil
}


func hashWithSha256(plaintext string) (string, error) {
	h := sha256.New()
	_, err := io.WriteString(h, plaintext)
	if err != nil{
		return "", err
	}
	r := h.Sum(nil)
	bs := hex.EncodeToString(r)
	return string(bs), nil
}


func newCipherBlock(key string) (cipher.Block, error){
	hashedKey, err := hashWithSha256(key)
	if err != nil{
		return nil, err
	}
	bs, err := hex.DecodeString(hashedKey)
	if err != nil{
		return nil, err
	}
	return aes.NewCipher(bs[:])
}


func generatePairOfKeys(bitSizeOfPrivateKey int) (*rsa.PrivateKey, crypto.PublicKey, error){
	priv, err := rsa.GenerateKey(rand.Reader, bitSizeOfPrivateKey)
	if err != nil{
		return nil, nil, err
	}

	return priv, priv.Public(), nil
}


func main() {
	fmt.Println("started!")
	r, err := hashWithSha256("faruqtolu")
	if err != nil{
		log.Fatal(err)
	}
	fmt.Println(r)

	pt := "Helloowo!ofme"

	ct, err := encrypt("faruq", pt)
	if err != nil{
		log.Fatalln(err)
	}


	fmt.Println(ct)

	ptt, err := decrypt("faruq", ct)
	if err != nil{
		log.Fatalln(err)
	}


	fmt.Println(ptt)


	priv, pub, err := generatePairOfKeys(2048)
	if err != nil{
		log.Fatalln(err)
	}

	options := rsa.OAEPOptions{
		crypto.SHA256,
		[]byte("label"),
	}

	message := []byte("Hey faruq!")
	fmt.Println("pub key size",pub.(*rsa.PublicKey).Size())
	fmt.Println(sha256.New().Size())

	rsact, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub.(*rsa.PublicKey), message, options.Label)
	if err != nil{
		log.Fatalln(err)
	}

	fmt.Println("RSA ciphertext", hex.EncodeToString(rsact))

	rsapt, err := priv.Decrypt(rand.Reader,rsact, &options)
	if err != nil{
		log.Fatalln(err)
	}

	fmt.Println("RSA plaintext", string(rsapt))


	//hmac
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte("Hey there!"))
	macBS := mac.Sum(nil)
	equal := hmac.Equal(macBS, macBS)
	fmt.Println(equal)






}

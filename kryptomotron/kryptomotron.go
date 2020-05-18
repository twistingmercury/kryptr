package kryptomotron

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"strings"
	"time"

	mrand "math/rand"
)

const (
	prvKey = "kryptr_rsa"
	pubKey = "kryptr_rsa.pub"
	encKey = "kryptr_enc"
)

// NewKeys creates a new secured encryption set.
func NewKeys() (r string, err error) {
	prvk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	pubk := &prvk.PublicKey

	dir, err := getConfigPath()
	if err != nil {
		return
	}

	pubBits := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pubk),
		},
	)
	if err != nil {
		return
	}

	pubf, err := os.Create(path.Join(*dir, pubKey))
	if err != nil {
		return
	}
	pubf.Write(pubBits)

	prvBits := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(prvk),
		},
	)
	if err != nil {
		return
	}

	prvf, err := os.Create(path.Join(*dir, prvKey))
	if err != nil {
		return
	}
	prvf.Write(prvBits)

	pwd := newPassword()
	r = string(pwd)

	c, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, pubk, pwd, nil)
	if err != nil {
		return
	}

	bc := base64.StdEncoding.EncodeToString(c)
	encf, err := os.Create(path.Join(*dir, encKey))
	_, err = encf.WriteString(bc)

	return
}

func newPassword() []byte {
	var (
		lcs = []rune("abcdedfghijklmnopqrst")
		ucs = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		scs = []rune("~!@#$%^&*?|=_+/.,<>:;")
		ncs = []rune("0123456789")
	)

	var b strings.Builder

	mrand.Seed(time.Now().Unix())
	var chars = [][]rune{lcs, ucs, scs, ncs}
	for _, c := range chars {
		for i := 0; i < 8; i++ {
			r := mrand.Intn(len(c))
			b.WriteRune(c[r])
		}
	}

	pwdr := []byte(b.String())

	mrand.Shuffle(len(pwdr), func(i, j int) {
		pwdr[i], pwdr[j] = pwdr[j], pwdr[i]
	})

	return pwdr
}

func getConfigPath() (p *string, err error) {
	u, err := user.Current()
	if err != nil {
		return
	}

	sp := path.Join(u.HomeDir, ".kryptr.d")

	if _, err := os.Stat(sp); os.IsNotExist(err) {
		os.Mkdir(sp, 0755)
	}

	p = &sp
	return
}

func getKey() (key []byte, err error) {
	root, err := getConfigPath()
	if err != nil {
		return
	}

	ePath := path.Join(*root, encKey)
	buf, err := ioutil.ReadFile(ePath)
	if err != nil {
		return
	}

	pwdc, err := base64.StdEncoding.DecodeString(string(buf))
	if err != nil {
		return
	}
	pkPath := path.Join(*root, prvKey)
	bits, err := ioutil.ReadFile(pkPath)
	if err != nil {
		return
	}

	pk, err := bytesToPK(bits)
	if err != nil {
		return
	}

	return rsa.DecryptOAEP(
		sha512.New(),
		rand.Reader,
		pk,
		pwdc,
		nil,
	)
}

func bytesToPK(bits []byte) (*rsa.PrivateKey, error) {
	var err error

	block, _ := pem.Decode(bits)
	blockBytes := block.Bytes
	ok := x509.IsEncryptedPEMBlock(block)

	if ok {
		blockBytes, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(blockBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// Encrypt encrypts the bytes.
func Encrypt(src []byte, out string) (err error) {
	if src == nil || len(src) == 0 {
		return errors.New("encrypt target is empty or nil")
	}

	key, err := getKey()
	if err != nil {
		return
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if err != nil {
		return
	}

	crypt := gcm.Seal(nonce, nonce, src, nil)
	b64crypt := make([]byte, base64.RawStdEncoding.EncodedLen(len(crypt)))

	base64.RawStdEncoding.Encode(b64crypt, crypt)

	ioutil.WriteFile(fmt.Sprintf("%s", out), b64crypt, 0755)

	return
}

// Decrypt decrypts the bytes.
func Decrypt(src []byte, out string) (err error) {

	if src == nil || len(src) == 0 {
		return errors.New("decryption target is empty or nil")
	}

	crypt := make([]byte, base64.RawStdEncoding.DecodedLen(len(src)))
	_, err = base64.RawStdEncoding.Decode(crypt, src)
	if err != nil {
		return
	}

	key, err := getKey()
	if err != nil {
		return
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return
	}

	nonceSize := gcm.NonceSize()
	if len(crypt) < nonceSize {
		return fmt.Errorf("nonceSize > src")
	}

	nonce, crypt := crypt[:nonceSize], crypt[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, crypt, nil)
	if err != nil {
		return
	}

	if len(out) == 0 {
		fmt.Println(string(plaintext))
	} else {
		ioutil.WriteFile(out, plaintext, 0755)
	}

	return
}

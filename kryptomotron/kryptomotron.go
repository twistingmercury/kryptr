package kryptomotron

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path"
	"strings"
	"time"

	mrand "math/rand"
)

const (
	prvKey    = "kryptr_rsa"
	pubKey    = "kryptr_rsa.pub"
	encKey    = "kryptr_enc"
	encodeStr = "+!@#0123456789$%:|ABCDEHTUVWacdeifXYZ^&*+?klmnopMNPQRSqrstuvwxyz"
)

var (
	lcs   = []byte("abcdedfghijklmnopqrstuvwxyz")
	ucs   = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	scs   = []byte("~!@#$%^&*?|=_+[]{}.,<>:;")
	ncs   = []byte("0123456789")
	chars = [][]byte{lcs, ucs, scs, ncs}
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

	pwd := newSalt()
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

// Kryptomogrify performs the work desired upon the input file.
func Kryptomogrify(in, out string, enc, dec bool) (err error) {
	src, err := read(in)

	if err != nil {
		return
	}

	switch {
	case (enc && dec) || (!enc && !dec):
		err = errors.New("the encrypt flag and decrypt flag are mutually exclusive")
	case enc:
		err = encrypt(src, out)
		if err != nil {
			return
		}
	case dec:
		err = decrypt(src, out)
	default:
		flag.Usage()
	}

	return
}

// Recover allows one to recover a file encrypted with an older pwd.
func Recover(in, out, pwd string) (err error) {
	src, err := read(in)
	if err != nil {
		return
	}

	if src == nil || len(src) == 0 {
		return errors.New("input file target is empty or nil")
	}

	crypt := make([]byte, base64.RawStdEncoding.DecodedLen(len(src)))
	_, err = base64.RawStdEncoding.Decode(crypt, src)
	if err != nil {
		return
	}

	nonce, gcm, err := getCipher([]byte(pwd))
	if err != nil {
		return
	}

	nonceSize := gcm.NonceSize()
	nonce, crypt = crypt[:nonceSize], crypt[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, crypt, nil)
	if err != nil {
		return
	}

	return ioutil.WriteFile(out, plaintext, 0755)
}

func newSalt() []byte {
	var b strings.Builder

	mrand.Seed(time.Now().Unix())
	for _, c := range chars {
		for i := 0; i < 8; i++ {
			r := mrand.Intn(len(c))
			b.WriteByte(c[r])
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

func getSalt() (salt []byte, err error) {
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

	return rsa.DecryptOAEP(sha512.New(), rand.Reader, pk, pwdc, nil)
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

func getCipher(key []byte) (nonce []byte, gcm cipher.AEAD, err error) {
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err = cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	return
}

func encrypt(src []byte, out string) (err error) {
	pwd, err := getPwd()

	if len(pwd) != 32 {
		return fmt.Errorf("invalid key length: %d", len(pwd))
	}

	if err != nil {
		return
	}

	nonce, gcm, err := getCipher(pwd)
	if err != nil {
		return
	}

	crypt := gcm.Seal(nonce, nonce, src, nil)

	return ioutil.WriteFile(fmt.Sprintf("%s", out), crypt, 0755)
}

func decrypt(src []byte, out string) (err error) {
	key, err := getPwd()
	if err != nil {
		return
	}

	nonce, gcm, err := getCipher(key)
	if err != nil {
		return
	}

	nonceSize := gcm.NonceSize()
	nonce, crypt := src[:nonceSize], src[nonceSize:]

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

func read(in string) (src []byte, err error) {
	if len(in) == 0 {
		err = errors.New("input file name is required")
		return
	}
	_, err = os.Stat(in)
	if err != nil {
		return
	}

	src, err = ioutil.ReadFile(in)
	if err != nil {
		return
	}

	if src == nil || len(src) == 0 {
		err = errors.New("input file target is empty or nil")
		return
	}

	return src, nil
}

func getPwd() ([]byte, error) {
	interfaces, err := net.Interfaces()
	var mac []byte
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
				mac = []byte(i.HardwareAddr.String())
				break
			}
		}
	}

	n, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	bits := append(mac, n...)

	salt, err := getSalt()
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(bits)
	hash := h.Sum(salt)

	e := base64.NewEncoding(encodeStr)
	pwd := make([]byte, e.EncodedLen(len(hash)))
	e.Encode(pwd, hash)

	return pwd[:32], nil
}

//This ECIES (Elliptic Curve Integrated Encryption Scheme) has been largery inspired by https://github.com/ecies/go
//However, we stick to using the the btcec library. the methods have been written with educational intention (step-by-step demonstration)
//Santander Blockchain Lab 2020

package ecies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/hkdf"
)

//Encrypt a message using an EC public key as a start
//Internally an ephemeral key is generated.
//If kdf flag is true, then hkdf will be used to  derive the key from the shared secret
func ECEncryptPub(pubkey *btcec.PublicKey, msg []byte, kdf bool) ([]byte, error) {
	// Generate ephemeral key
	ek, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}
	return ECEncryptPubPriv(pubkey, ek, msg, kdf)
}

// Encrypt encrypts a passed message with a receiver public key and an (ephemeral) private key
// returns ciphertext or encryption error
// The byte slice returned conatins the ethpemeral public key [0-64], the iv [65-76],
// and the cipthertext with auth tag at the end
func ECEncryptPubPriv(pubkey *btcec.PublicKey, ephKey *btcec.PrivateKey, msg []byte, kdf bool) ([]byte, error) {
	var ct bytes.Buffer

	ct.Write(ephKey.PubKey().SerializeUncompressed())

	// Derive shared secret
	ss := btcec.GenerateSharedSecret(ephKey, pubkey)
	var sk []byte
	if kdf {
		// Derive synkey from shared secret
		var err error
		sk, err = hkdfWrapper(ss, 32, nil, nil)
		if err != nil {
			return nil, err
		}
	} else {
		sk = ss[:32]
	}

	// AES encryption
	block, err := aes.NewCipher(sk)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %w", err)
	}

	ct.Write(nonce)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot create aes gcm: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, msg, nil)

	//Note that the TAG will be written at the end of the ciphertext
	ct.Write(ciphertext)
	return ct.Bytes(), nil
}

//Recovers the ephemeral key and calls ECDecryptPrivPub()
func ECDecryptPriv(privkey *btcec.PrivateKey, msg []byte, kdf bool) ([]byte, error) {
	// Recover ephemeral sender public key
	if len(msg) < (1 + 32 + 32 + 12 + 16) {
		return nil, fmt.Errorf("invalid length of message")
	}

	ethPubkey := &btcec.PublicKey{
		Curve: btcec.S256(),
		X:     new(big.Int).SetBytes(msg[1:33]),
		Y:     new(big.Int).SetBytes(msg[33:65]),
	}
	msg = msg[65:]
	return ECDecryptPrivPub(privkey, ethPubkey, msg, kdf)
}

// Decrypt decrypts a passed message with a receiver private key and ephemeral public key
// returns plaintext or decryption error
func ECDecryptPrivPub(privkey *btcec.PrivateKey, pubkey *btcec.PublicKey, msg []byte, kdf bool) ([]byte, error) {
	// Message cannot be less than length of public key (65) + nonce (16) + tag (16)

	// Derive shared secret
	ss := btcec.GenerateSharedSecret(privkey, pubkey)
	var skey []byte
	if kdf { // Derive shared symmetric key from the secret
		var err error
		skey, err = hkdfWrapper(ss, 32, nil, nil)
		if err != nil {
			return nil, err
		}
	} else { //sometimes kdf gets in the way of interop...

		skey = ss[:32]
	}

	nonce := msg[:12]

	// Golang-accepted ciphertext has TAG at the end of the byte array
	ciphertext := msg[12:]

	block, err := aes.NewCipher(skey)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot create gcm cipher: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

//Utility wraper around the hkdf secure derivation
//A slice of requested "size" length will be derived and returned
func hkdfWrapper(secret []byte, size int, salt, info []byte) (key []byte, err error) {
	key = make([]byte, size)
	kdf := hkdf.New(sha256.New, secret, salt, info)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("cannot read secret from HKDF reader: %w", err)
	}

	return key, nil
}

func EcPubKeyBytesToPem(rawkey []byte) string {
	meatBytes := append(ecPubKeyPreamble, rawkey...)
	encMeatBytes := make([]byte, base64.StdEncoding.EncodedLen(len(meatBytes)))
	base64.StdEncoding.Encode(encMeatBytes, meatBytes)
	out := append(ecpbkHeader, insertNewLineEvery64(encMeatBytes)...)
	out = append(out, ecpbkFooter...)
	return string(out)
}

func insertNewLineEvery64(in []byte) (out []byte) {
	i := 64
	for ; i < len(in); i = i + 64 {
		out = append(out, in[i-64:i]...)
		out = append(out, '\n')
	}
	out = append(out, in[i-64:]...)
	return
}

var ecpbkHeader = []byte("-----BEGIN PUBLIC KEY-----\n")
var ecpbkFooter = []byte("\n-----END PUBLIC KEY-----")
var ecPubKeyPreamble = []byte{48, 86, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 10, 3, 66, 0}

// EncodePrivateKey encodes an ECDSA private key to PEM format.
func ECPrivateKeyToPEM(key *ecdsa.PrivateKey) (string, error) {
	derKey, err := MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}

	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derKey,
	}
	s := string(pem.EncodeToMemory(keyBlock))
	return s, nil
}

// Now I need to hijack this code from x509 because they do not know the Koblitz OID :-(
func MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	//oid, ok := oidFromNamedCurve(key.Curve)
	//if !ok {
	//	return nil, errors.New("x509: unknown elliptic curve")
	//}
	oid := asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	privateKeyBytes := key.D.Bytes()
	paddedPrivateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

const SEKPC256K1OID = "2b8104000a"

func ParseKoblitzPubPem(pemstring string) (*btcec.PublicKey, error) {
	blk, _ := pem.Decode([]byte(pemstring))
	if blk == nil {
		return nil, fmt.Errorf("Null Block")
	}
	if len(blk.Bytes) < len(ecPubKeyPreamble) {
		return nil, fmt.Errorf("Block too short")
	}
	return btcec.ParsePubKey(blk.Bytes[len(ecPubKeyPreamble):], btcec.S256())

}

//TODO Rhis is a hack because I cannot do any better parsing asn1 :-(
func ParseKoblitzPrivPem(pemstring string) (*btcec.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(pemstring))
	if blk == nil {
		return nil, fmt.Errorf("Null Block")
	}
	if len(blk.Bytes) < len(ecPubKeyPreamble) {
		return nil, fmt.Errorf("Block too short")
	}
	keybytes := blk.Bytes[7:39]
	pk, _ := btcec.PrivKeyFromBytes(btcec.S256(), keybytes)
	return pk, nil
}

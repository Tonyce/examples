package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
)

func main() {

	var private_key *rsa.PrivateKey
	var public_key *rsa.PublicKey
	var plain_text, encrypted, decrypted, label []byte
	var err error

	plain_text = []byte("Plain text message to be encrypted")

	//Generate Private Key
	if private_key, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
		log.Fatal(err)
	}
	fmt.Println(private_key)

	// Precompute some calculations -- Calculations that speed up private key operations in the future
	private_key.Precompute()

	//Validate Private Key -- Sanity checks on the key
	if err = private_key.Validate(); err != nil {
		log.Fatal(err)
	}

	//Public key address (of an RSA key)
	public_key = &private_key.PublicKey

	encrypted = encrypt_oaep(public_key, plain_text, label)
	decrypted = decrypt_oaep(private_key, encrypted, label)

	fmt.Printf("OAEP Encrypted [%s] to \n[%x]\n", string(plain_text), encrypted)
	fmt.Printf("OAEP Decrypted [%x] to \n[%s]\n", encrypted, decrypted)

	// To use existing private key (Skipping the GenerateKey, Precompute, Validation steps shown above)
	// This reads pem file and retrieves the public, private key needed to encrypt data
	use_exsiting_keys()

}

func use_exsiting_keys() {

	var pem_file_path string
	var err error
	var block *pem.Block
	var private_key *rsa.PrivateKey
	var public_key *rsa.PublicKey
	var pem_data, plain_text, encrypted, decrypted, label []byte

	plain_text = []byte("Plain text message to be encrypted")

	// A PEM file can contain a Private key among others (Public certificate, Intermidiate Certificate, Root certificate, ...)
	pem_file_path = "/path/to/pem/file"
	if pem_data, err = ioutil.ReadFile(pem_file_path); err != nil {
		log.Fatalf("Error reading pem file: %s", err)
	}

	//Package pem implements the PEM data encoding, most commonly used in TLS keys and certificates.
	//Decode will find the next PEM formatted block (certificate, private key etc) in the input.
	//Expected Block type "RSA PRIVATE KEY"
	//http://golang.org/pkg/encoding/pem/
	if block, _ = pem.Decode(pem_data); block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatal("No valid PEM data found")
	}

	//x509 parses X.509-encoded keys and certificates.
	//ParsePKCS1PrivateKey returns an RSA private key from its ASN.1 PKCS#1 DER encoded form.
	if private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		log.Fatalf("Private key can't be decoded: %s", err)
	}

	public_key = &private_key.PublicKey

	encrypted = encrypt_oaep(public_key, plain_text, label)
	decrypted = decrypt_oaep(private_key, encrypted, label)

	fmt.Printf("OAEP Encrypted [%s] to \n[%x]\n", string(plain_text), encrypted)
	fmt.Printf("OAEP Decrypted [%x] to \n[%s]\n", encrypted, decrypted)

	return
}

//OAEP Encrypt
func encrypt_oaep(public_key *rsa.PublicKey, plain_text, label []byte) (encrypted []byte) {
	var err error
	var md5_hash hash.Hash

	md5_hash = md5.New()

	if encrypted, err = rsa.EncryptOAEP(md5_hash, rand.Reader, public_key, plain_text, label); err != nil {
		log.Fatal(err)
	}
	return
}

func decrypt_oaep(private_key *rsa.PrivateKey, encrypted, label []byte) (decrypted []byte) {
	var err error
	var md5_hash hash.Hash

	md5_hash = md5.New()
	if decrypted, err = rsa.DecryptOAEP(md5_hash, rand.Reader, private_key, encrypted, label); err != nil {
		log.Fatal(err)
	}
	return
}

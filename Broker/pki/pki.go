package pki

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func ValidateCertificate(data []byte) (string, *rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return "", nil, fmt.Errorf("invalid certificate encoding")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, err
	}

	caData, err := ioutil.ReadFile("ca-public-key.pem")
	if err != nil {
		return "", nil, err
	}

	nBlock, _ := pem.Decode(caData)
	caCert, err := x509.ParseCertificate(nBlock.Bytes)
	if err != nil {
		return "", nil, err
	}

	hash := sha256.New()
	hash.Write(cert.RawTBSCertificate)
	hashData := hash.Sum(nil)
	err = rsa.VerifyPKCS1v15(caCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashData, cert.Signature)
	if err != nil {
		fmt.Println(err)
		return "", nil, errors.New("certificate not signed by CA")
	}

	return cert.Subject.CommonName, cert.PublicKey.(*rsa.PublicKey), nil
}

func ValidateSignature(message []byte, signature []byte, key *rsa.PublicKey) (bool, error) {
	hash := sha256.New()
	_, err := hash.Write(message)
	if err != nil {
		return false, err
	}
	hashSum := hash.Sum(nil)
	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hashSum, signature)
	if err != nil {
		return false, nil
	}
	return true, nil
}

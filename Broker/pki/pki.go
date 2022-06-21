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

func ValidateCertificate(data []byte) (string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("invalid certificate encoding")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	caData, err := ioutil.ReadFile("ca-public-key.pem")
	if err != nil {
		return "", err
	}

	nBlock, _ := pem.Decode(caData)
	caCert, err := x509.ParseCertificate(nBlock.Bytes)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write(cert.RawTBSCertificate)
	hashData := hash.Sum(nil)
	err = rsa.VerifyPKCS1v15(caCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashData, cert.Signature)
	if err != nil {
		fmt.Println(err)
		return "", errors.New("certificate not signed by CA")
	}

	return cert.Subject.CommonName, nil
}

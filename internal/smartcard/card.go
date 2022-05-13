/*
Copyright 2022 T-Systems Multimedia Solutions GmbH
SPDX-License-Identifier: MIT
*/

package smartcard

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"pault.ag/go/pkcs7"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"github.com/sirupsen/logrus"
)

const (
	pkcs11LibEnvironment = "PKCS11_LIB"
)

type MatchingCertificate struct {
	Certificate   *x509.Certificate
	RecipientInfo *pkcs7.RecipientInfo
	ID            []byte
}

func matchCertificate(object p11.Object, recipients *pkcs7.Recipients) (*MatchingCertificate, error) {
	label, err := object.Label()
	if err != nil {
		return nil, fmt.Errorf("could not get label: %w", err)
	}

	certID, err := object.Attribute(pkcs11.CKA_ID)
	if err != nil {
		return nil, fmt.Errorf("could not get id: %w", err)
	}

	logrus.Debugf("found certificate with label '%s' and id '%s'", label, hex.EncodeToString(certID))

	value, err := object.Value()
	if err != nil {
		return nil, fmt.Errorf("could not get certificate data: %w", err)
	}

	x509Cert, err := x509.ParseCertificates(value)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate: %w", err)
	}

	logrus.Debugf("got certificate %s (issued by %s)", x509Cert[0].SerialNumber, x509Cert[0].Issuer)

	found, err := recipients.Find(*x509Cert[0])
	if err != nil {
		logrus.Debugf("no recipient info for: %v", err)

		return nil, nil
	}

	logrus.Infof("the certificate with label %s can be used", label)

	return &MatchingCertificate{
		ID:            certID,
		RecipientInfo: found,
		Certificate:   x509Cert[0],
	}, nil
}

// GetDecryptionKey retrieves a valid secret key for one of the recipients given in the `recipients` parameter.
func GetDecryptionKey(p11Module string, recipients *pkcs7.Recipients, slotNum int) ([]byte, error) {
	m, err := loadPkcs11Module(p11Module)
	if err != nil {
		return nil, fmt.Errorf("could not load PKCS#11 module: %w", err)
	}

	defer m.Destroy()

	session, err := performSmartCardLogin(m, slotNum)
	if err != nil {
		return nil, fmt.Errorf("could not open smart card session: %w", err)
	}

	defer func(session p11.Session) {
		err := session.Close()
		if err != nil {
			logrus.Errorf("could not close token session: %v", err)
		}
	}(session)

	attributes := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE)}

	certs, err := session.FindObjects(attributes)
	if err != nil {
		return nil, fmt.Errorf("could not find certificates: %w", err)
	}

	matching, err := findMatchingCertificate(recipients, certs)
	if err != nil {
		return nil, fmt.Errorf("certificate matching failed: %w", err)
	}

	privateKey, err := getCorrespondingPrivateKey(session, matching)
	if err != nil {
		return nil, fmt.Errorf("private key error: %w", err)
	}

	mechanism, err := chooseMechanism(matching.RecipientInfo.KeyEncryptionAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("could not find matching decryption mechanism: %w", err)
	}

	publicKey, ok := matching.Certificate.PublicKey.(crypto.PublicKey)
	if !ok {
		return nil, errors.New("cannot not use found public key as crypto.PublicKey")
	}

	decrypter := newPkcs11Decrypter(mechanism, privateKey, &publicKey)

	var opts crypto.DecrypterOpts

	decryptedKey, err := matching.RecipientInfo.Decrypt(rand.Reader, decrypter, opts)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt with private key: %w", err)
	}

	return decryptedKey, nil
}

func performSmartCardLogin(m *p11.Module, slotNum int) (p11.Session, error) {
	slots, err := m.Slots()
	if err != nil {
		return nil, fmt.Errorf("could not get list of token slots: %w", err)
	}

	if len(slots) < slotNum+1 {
		return nil, fmt.Errorf("no valid token/smart card found in slot %d", slotNum)
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logSlotInfo(slots)
	}

	pin, err := GetPin()
	if err != nil {
		return nil, err
	}

	session, err := slots[slotNum].OpenSession()
	if err != nil {
		return nil, fmt.Errorf("could not open smartcard session")
	}

	err = session.Login(string(pin))
	if err != nil {
		err := session.Close()
		if err != nil {
			return nil, fmt.Errorf("could not close smartcard session: %w", err)
		}

		return nil, fmt.Errorf("could not login to smartcard: %w", err)
	}

	return session, nil
}

func loadPkcs11Module(p11Module string) (*p11.Module, error) {
	fileName, err := determineP11Module(p11Module)
	if err != nil {
		return nil, err
	}

	m, err := p11.OpenModule(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not open PKCS#11 module: %w", err)
	}

	info, err := m.Info()
	if err != nil {
		return nil, fmt.Errorf("could not get module info: %w", err)
	}

	logrus.Debugf("loaded module %v", info)

	return &m, nil
}

func getCorrespondingPrivateKey(session p11.Session, matching *MatchingCertificate) (*p11.PrivateKey, error) {
	keySearch := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, matching.ID),
	}

	keyObject, err := session.FindObject(keySearch)
	if err != nil {
		return nil, fmt.Errorf("could not find keys: %w", err)
	}

	label, err := keyObject.Label()

	if err != nil {
		return nil, fmt.Errorf("could not get label for private key: %w", err)
	}

	logrus.Debugf("found private key with label %s", label)

	privateKey := p11.PrivateKey(keyObject)

	return &privateKey, nil
}

func findMatchingCertificate(recipients *pkcs7.Recipients, certs []p11.Object) (*MatchingCertificate, error) {
	var matching *MatchingCertificate

	for _, object := range certs {
		var err error

		matching, err = matchCertificate(object, recipients)
		if err != nil {
			logrus.Error(err)

			continue
		}

		if matching != nil {
			break
		}
	}

	if matching == nil {
		return nil, errors.New("no matching certificate found on smart card")
	}

	logrus.Infof(
		"found matching cert: %s (issued by %s)",
		matching.Certificate.SerialNumber,
		matching.Certificate.Issuer,
	)
	logrus.Debugf("corresponding recipient info: %s", matching.RecipientInfo.IssuerAndSerialNumber.Serial)

	return matching, nil
}

func logSlotInfo(slots []p11.Slot) {
	for index, slot := range slots {
		slotInfo, err := slot.Info()
		if err != nil {
			logrus.Errorf("could not get slot info: %v", err)

			return
		}

		logrus.Debugf("slot %d: %+v", index, slotInfo.SlotDescription)
	}
}

func determineP11Module(p11Module string) (string, error) {
	if p11Module == "" {
		p11Module = os.Getenv(pkcs11LibEnvironment)
	}

	if p11Module == "" {
		return "", fmt.Errorf(
			"no PKCS#11 module library has been specified, use either the"+
				" -p11module command line parameter or the %s environment variable",
			pkcs11LibEnvironment,
		)
	}

	return p11Module, nil
}

type pkcs11Decrypter struct {
	private   *p11.PrivateKey
	public    *crypto.PublicKey
	mechanism *pkcs11.Mechanism
}

func (p *pkcs11Decrypter) Public() crypto.PublicKey {
	return *p.public
}

func (p *pkcs11Decrypter) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) (plaintext []byte, err error) {
	decrypted, err := p.private.Decrypt(*p.mechanism, msg)

	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return decrypted, nil
}

func newPkcs11Decrypter(mechanism *pkcs11.Mechanism, key *p11.PrivateKey, public *crypto.PublicKey) *pkcs11Decrypter {
	return &pkcs11Decrypter{mechanism: mechanism, private: key, public: public}
}

func chooseMechanism(algorithm pkix.AlgorithmIdentifier) (*pkcs11.Mechanism, error) {
	rsaEncryption := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	rsaOAEPEncryption := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}

	if algorithm.Algorithm.Equal(rsaEncryption) {
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), nil
	}

	if algorithm.Algorithm.Equal(rsaOAEPEncryption) {
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, nil), nil
	}

	return nil, fmt.Errorf("unsupported algorithm %s", algorithm.Algorithm)
}

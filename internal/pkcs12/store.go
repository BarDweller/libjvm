/**
Copyright (c) 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**/

package pkcs12

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"unicode/utf16"
)

type TrustStoreEntry struct {
	Cert         *x509.Certificate
	FriendlyName string
}

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type pkcs12Attribute struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type safeBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type certBag struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

var (
	oidDataContentType     = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidFriendlyName        = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 20})
	oidAnyExtendedKeyUsage = asn1.ObjectIdentifier([]int{2, 5, 29, 37, 0})
	oidJavaTrustStore      = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 113894, 746875, 1, 1})

	oidCertBag = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 3})

	oidCertTypeX509Certificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 1})
)

func EncodeTrustStoreWithoutPassword(rand io.Reader, certs []*x509.Certificate) (pfxData []byte, err error) {
	var certsWithFriendlyNames []TrustStoreEntry
	for _, cert := range certs {
		certsWithFriendlyNames = append(certsWithFriendlyNames, TrustStoreEntry{
			Cert:         cert,
			FriendlyName: cert.Subject.String(),
		})
	}
	return encode(rand, certsWithFriendlyNames)
}

func encode(rand io.Reader, entries []TrustStoreEntry) (pfxData []byte, err error) {
	var pfx pfxPdu
	pfx.Version = 3

	var certAttributes []pkcs12Attribute

	extKeyUsageOidBytes, err := asn1.Marshal(oidAnyExtendedKeyUsage)
	if err != nil {
		return nil, err
	}

	certAttributes = append(certAttributes, pkcs12Attribute{
		Id: oidJavaTrustStore,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
			Bytes:      extKeyUsageOidBytes,
		},
	})

	var certBags []safeBag
	for _, entry := range entries {

		bmpFriendlyName, err := bmpString(entry.FriendlyName)
		if err != nil {
			return nil, err
		}

		encodedFriendlyName, err := asn1.Marshal(asn1.RawValue{
			Class:      0,
			Tag:        30,
			IsCompound: false,
			Bytes:      bmpFriendlyName,
		})
		if err != nil {
			return nil, err
		}

		friendlyName := pkcs12Attribute{
			Id: oidFriendlyName,
			Value: asn1.RawValue{
				Class:      0,
				Tag:        17,
				IsCompound: true,
				Bytes:      encodedFriendlyName,
			},
		}

		certBag, err := makeCertBag(entry.Cert.Raw, append(certAttributes, friendlyName))
		if err != nil {
			return nil, err
		}
		certBags = append(certBags, *certBag)
	}

	var authenticatedSafe [1]contentInfo
	if authenticatedSafe[0], err = makeUnsafeContents(rand, certBags); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, errors.New("pkcs12: error writing P12 data: " + err.Error())
	}
	return
}

func makeCertBag(certBytes []byte, attributes []pkcs12Attribute) (certBag *safeBag, err error) {
	certBag = new(safeBag)
	certBag.Id = oidCertBag
	certBag.Value.Class = 2
	certBag.Value.Tag = 0
	certBag.Value.IsCompound = true
	if certBag.Value.Bytes, err = encodeCertBag(certBytes); err != nil {
		return nil, err
	}
	certBag.Attributes = attributes
	return
}

func encodeCertBag(x509Certificates []byte) (asn1Data []byte, err error) {
	var bag certBag
	bag.Id = oidCertTypeX509Certificate
	bag.Data = x509Certificates
	if asn1Data, err = asn1.Marshal(bag); err != nil {
		return nil, errors.New("pkcs12: error encoding cert bag: " + err.Error())
	}
	return asn1Data, nil
}

func makeUnsafeContents(rand io.Reader, bags []safeBag) (ci contentInfo, err error) {
	var data []byte
	if data, err = asn1.Marshal(bags); err != nil {
		return
	}

	ci.ContentType = oidDataContentType
	ci.Content.Class = 2
	ci.Content.Tag = 0
	ci.Content.IsCompound = true
	if ci.Content.Bytes, err = asn1.Marshal(data); err != nil {
		return
	}
	return
}

func bmpString(s string) ([]byte, error) {

	ret := make([]byte, 0, 2*len(s)+2)

	for _, r := range s {
		if t, _ := utf16.EncodeRune(r); t != 0xfffd {
			return nil, errors.New("pkcs12: string contains characters that cannot be encoded in UCS-2")
		}
		ret = append(ret, byte(r/256), byte(r%256))
	}

	return ret, nil
}

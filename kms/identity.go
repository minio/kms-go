// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strconv"
	"time"

	"aead.dev/mtls"
)

// Privilege represents an access control role of identities.
// An identity with a higher privilege has access to more APIs.
//
// As a general security best practice, identities should have
// the lowest privilege required to perform their tasks.
type Privilege uint

// Supported privileges.
const (
	// SysAdmin is the highest privilege within the KMS, similar to
	// root on unix systems. An identity with the SysAdmin privilege
	// has access to all public APIs. Identities with the SysAdmin
	// privilege should be used for provisioning and to manage the
	// KMS cluster.
	SysAdmin Privilege = iota + 1

	// Admin is the privilege that allows identities to perform all
	// operations within an enclave. In contrast to sysadmins, admins
	// cannot peform cluster management tasks or manage enclaves.
	Admin

	// User is the privilege with limited access within an enclave.
	// Identities with the User privilege can only perform operations
	// within an enclave and only with an associated policy allowing
	// the API operation.
	User
)

// ParsePrivilege parses s as privilege string representation.
func ParsePrivilege(s string) (Privilege, error) {
	switch s {
	default:
		return 0, errors.New("kms: invalid privilege '" + s + "'")
	case "SysAdmin":
		return SysAdmin, nil
	case "Admin":
		return Admin, nil
	case "User":
		return User, nil
	}
}

// String returns the string representation of the Privilege.
func (p Privilege) String() string {
	switch p {
	case SysAdmin:
		return "SysAdmin"
	case Admin:
		return "Admin"
	case User:
		return "User"
	default:
		return "!INVALID:" + strconv.Itoa(int(p))
	}
}

// GenerateCertificate generates a new self-signed TLS certificate
// from the given template using the APIKey's private and public key.
//
// The template may be nil. In such a case the returned certificate
// is generated using a default template and valid for 90 days.
func GenerateCertificate(key mtls.Signer, template *x509.Certificate) (tls.Certificate, error) {
	if template == nil {
		template = &x509.Certificate{
			Subject: pkix.Name{
				CommonName: key.Identity().String(),
			},
			NotBefore: time.Now().UTC(),
			NotAfter:  time.Now().UTC().Add(90 * 24 * time.Hour),
			KeyUsage:  x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
			BasicConstraintsValid: true,
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

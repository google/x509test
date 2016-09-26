package main

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

//////////////////////////////////////
// Copy of unexported code from crypto/x509/x509.go
var (
	OidAttribute          = asn1.ObjectIdentifier{2, 5, 4}
	OidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	OidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	OidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	OidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	OidSerialNumber       = asn1.ObjectIdentifier{2, 5, 4, 5}
	OidLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	OidProvince           = asn1.ObjectIdentifier{2, 5, 4, 8}
	OidStreetAddress      = asn1.ObjectIdentifier{2, 5, 4, 9}
	OidPostalCode         = asn1.ObjectIdentifier{2, 5, 4, 17}

	OidPseudonym           = asn1.ObjectIdentifier{2, 5, 4, 65}
	OidTitle               = asn1.ObjectIdentifier{2, 5, 4, 12}
	OidDnQualifier         = asn1.ObjectIdentifier{2, 5, 4, 46}
	OidName                = asn1.ObjectIdentifier{2, 5, 4, 41}
	OidSurname             = asn1.ObjectIdentifier{2, 5, 4, 4}
	OidGivenName           = asn1.ObjectIdentifier{2, 5, 4, 42}
	OidInitials            = asn1.ObjectIdentifier{2, 5, 4, 43}
	OidGenerationQualifier = asn1.ObjectIdentifier{2, 5, 4, 44}
)

var (
	OidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	OidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func OidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return OidNamedCurveP224, true
	case elliptic.P256():
		return OidNamedCurveP256, true
	case elliptic.P384():
		return OidNamedCurveP384, true
	case elliptic.P521():
		return OidNamedCurveP521, true
	}

	return nil, false
}

var (
	oidExtensionStandardArc           = asn1.ObjectIdentifier{2, 5, 29}
	OidExtensionSubjectKeyId          = asn1.ObjectIdentifier{2, 5, 29, 14}
	OidExtensionKeyUsage              = asn1.ObjectIdentifier{2, 5, 29, 15}
	OidExtensionExtendedKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	OidExtensionAuthorityKeyId        = asn1.ObjectIdentifier{2, 5, 29, 35}
	OidExtensionBasicConstraints      = asn1.ObjectIdentifier{2, 5, 29, 19}
	OidExtensionSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	OidExtensionCertificatePolicies   = asn1.ObjectIdentifier{2, 5, 29, 32}
	OidExtensionNameConstraints       = asn1.ObjectIdentifier{2, 5, 29, 30}
	OidExtensionCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
	OidExtensionAuthorityInfoAccess   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

//////////////////////////////////////

func oidForStandardExtension(oid asn1.ObjectIdentifier) bool {
	if oid.Equal(OidExtensionSubjectKeyId) ||
		oid.Equal(OidExtensionKeyUsage) ||
		oid.Equal(OidExtensionExtendedKeyUsage) ||
		oid.Equal(OidExtensionAuthorityKeyId) ||
		oid.Equal(OidExtensionBasicConstraints) ||
		oid.Equal(OidExtensionSubjectAltName) ||
		oid.Equal(OidExtensionCertificatePolicies) ||
		oid.Equal(OidExtensionNameConstraints) ||
		oid.Equal(OidExtensionCRLDistributionPoints) ||
		oid.Equal(OidExtensionAuthorityInfoAccess) {
		return true
	}
	return false
}

// oidInExtensions indicates whether the extension identified by oid is present in extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) (count int, critical bool) {
	for _, ext := range extensions {
		if ext.Id.Equal(oid) {
			count++
			if ext.Critical {
				critical = true
			}
		}
	}
	return
}

// String formatting for various X.509/ASN.1 types
func bitStringToString(b asn1.BitString) string {
	result := hex.EncodeToString(b.Bytes)
	bitsLeft := b.BitLength % 8
	if bitsLeft != 0 {
		result += " (" + strconv.Itoa(8-bitsLeft) + " unused bits)"
	}
	return result
}

func publicKeyAlgorithmToString(algo x509.PublicKeyAlgorithm) string {
	switch algo {
	case x509.RSA:
		return "rsaEncryption"
	case x509.DSA:
		return "dsaEncryption"
	case x509.ECDSA:
		return "id-ecPublicKey"
	default:
		return strconv.Itoa(int(algo))
	}
}

func appendHexData(buf *bytes.Buffer, data []byte, count int, prefix string) {
	for ii, byte := range data {
		if ii%count == 0 {
			if ii > 0 {
				buf.WriteString("\n")
			}
			buf.WriteString(prefix)
		}
		buf.WriteString(fmt.Sprintf("%02x:", byte))
	}
}

func curveOidToString(oid asn1.ObjectIdentifier) (t string, bitlen int) {
	switch {
	case oid.Equal(OidNamedCurveP224):
		return "secp224r1", 224
	case oid.Equal(OidNamedCurveP256):
		return "prime256v1", 256
	case oid.Equal(OidNamedCurveP384):
		return "secp384r1", 384
	case oid.Equal(OidNamedCurveP521):
		return "secp521r1", 521
	}
	return fmt.Sprintf("%s", oid), -1
}

func publicKeyToString(algo x509.PublicKeyAlgorithm, pub interface{}) string {
	var buf bytes.Buffer
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		bitlen := pub.N.BitLen()
		buf.WriteString(fmt.Sprintf("                Public Key: (%d bit)\n", bitlen))
		buf.WriteString("                Modulus:\n")
		data := pub.N.Bytes()
		appendHexData(&buf, data, 15, "                    ")
		buf.WriteString("\n")
		buf.WriteString(fmt.Sprintf("                Exponent: %d (0x%x)", pub.E, pub.E))
	case *dsa.PublicKey:
		buf.WriteString("                pub:\n")
		appendHexData(&buf, pub.Y.Bytes(), 15, "                    ")
		buf.WriteString("\n")
		buf.WriteString("                P:\n")
		appendHexData(&buf, pub.P.Bytes(), 15, "                    ")
		buf.WriteString("\n")
		buf.WriteString("                Q:\n")
		appendHexData(&buf, pub.Q.Bytes(), 15, "                    ")
		buf.WriteString("\n")
		buf.WriteString("                G:\n")
		appendHexData(&buf, pub.G.Bytes(), 15, "                    ")
	case *ecdsa.PublicKey:
		data := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := OidFromNamedCurve(pub.Curve)
		if !ok {
			return "                <unsupported elliptic curve>"
		}
		oidname, bitlen := curveOidToString(oid)
		buf.WriteString(fmt.Sprintf("                Public Key: (%d bit)\n", bitlen))
		buf.WriteString("                pub:\n")
		appendHexData(&buf, data, 15, "                    ")
		buf.WriteString("\n")
		buf.WriteString(fmt.Sprintf("                ASN1 OID: %s", oidname))
	default:
		buf.WriteString(fmt.Sprintf("%v", pub))
	}
	return buf.String()
}

func commaAppend(buf *bytes.Buffer, s string) {
	if buf.Len() > 0 {
		buf.WriteString(", ")
	}
	buf.WriteString(s)
}

func keyUsageToString(k x509.KeyUsage) string {
	var buf bytes.Buffer
	if k&x509.KeyUsageDigitalSignature != 0 {
		commaAppend(&buf, "Digital Signature")
	}
	if k&x509.KeyUsageContentCommitment != 0 {
		commaAppend(&buf, "Content Commitment")
	}
	if k&x509.KeyUsageKeyEncipherment != 0 {
		commaAppend(&buf, "Key Encipherment")
	}
	if k&x509.KeyUsageDataEncipherment != 0 {
		commaAppend(&buf, "Data Encipherment")
	}
	if k&x509.KeyUsageKeyAgreement != 0 {
		commaAppend(&buf, "Key Agreement")
	}
	if k&x509.KeyUsageCertSign != 0 {
		commaAppend(&buf, "Certificate Signing")
	}
	if k&x509.KeyUsageCRLSign != 0 {
		commaAppend(&buf, "CRL Signing")
	}
	if k&x509.KeyUsageEncipherOnly != 0 {
		commaAppend(&buf, "Encipher Only")
	}
	if k&x509.KeyUsageDecipherOnly != 0 {
		commaAppend(&buf, "Decipher Only")
	}
	return buf.String()
}

func extKeyUsageToString(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "TLS Web server authentication"
	case x509.ExtKeyUsageClientAuth:
		return "TLS Web client authentication"
	case x509.ExtKeyUsageCodeSigning:
		return "Signing of executable code"
	case x509.ExtKeyUsageEmailProtection:
		return "Email protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSEC end system"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSEC tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSEC user"
	case x509.ExtKeyUsageTimeStamping:
		return "Time stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP signing"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "Microsoft server gated cryptography"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "Netscape server gated cryptography"
	default:
		return "Unknown"
	}
}

func NameToString(name pkix.Name) string {
	var result bytes.Buffer
	addSingle := func(item string, prefix string) {
		if len(item) == 0 {
			return
		}
		if result.Len() > 0 {
			result.WriteString(", ")
		}
		result.WriteString(prefix)
		result.WriteString(item)
	}
	addList := func(items []string, prefix string) {
		for _, item := range items {
			addSingle(item, prefix)
		}
	}
	addList(name.Country, "C=")
	addList(name.Organization, "O=")
	addList(name.OrganizationalUnit, "OU=")
	addList(name.Locality, "L=")
	addList(name.Province, "ST=")
	addList(name.StreetAddress, "streetAddress=")
	addList(name.PostalCode, "postalCode=")
	addSingle(name.SerialNumber, "serialNumber=")
	addSingle(name.CommonName, "CN=")
	for _, atv := range name.Names {
		value, ok := atv.Value.(string)
		if !ok {
			continue
		}
		t := atv.Type
		if len(t) == 4 && t[0] == OidAttribute[0] && t[1] == OidAttribute[1] && t[2] == OidAttribute[2] {
			// OID is 'id-at N'
			switch t[3] {
			case OidCommonName[3], OidSerialNumber[3], OidCountry[3], OidLocality[3], OidProvince[3],
				OidStreetAddress[3], OidOrganization[3], OidOrganizationalUnit[3], OidPostalCode[3]:
				continue // covered by explicit fields
			case OidPseudonym[3]:
				addSingle(value, "pseudonym=")
				continue
			case OidTitle[3]:
				addSingle(value, "title=")
				continue
			case OidDnQualifier[3]:
				addSingle(value, "dnQualifier=")
				continue
			case OidName[3]:
				addSingle(value, "name=")
				continue
			case OidSurname[3]:
				addSingle(value, "surname=")
				continue
			case OidGivenName[3]:
				addSingle(value, "givenName=")
				continue
			case OidInitials[3]:
				addSingle(value, "initials=")
				continue
			case OidGenerationQualifier[3]:
				addSingle(value, "generationQualifier=")
				continue
			}
		}
		addSingle(value, t.String()+"=")
	}
	return result.String()
}

// CertificateToString generates a string describing the given certificate.
// The output roughly resembles that from openssl x509 -text.
func CertificateToString(cert *x509.Certificate) string {
	var result bytes.Buffer
	result.WriteString(fmt.Sprintf("Certificate:\n"))
	result.WriteString(fmt.Sprintf("    Data:\n"))
	result.WriteString(fmt.Sprintf("        Version: %d (%#[1]x)\n", cert.Version))
	result.WriteString(fmt.Sprintf("        Serial Number: %d (%#[1]x)\n", cert.SerialNumber))
	result.WriteString(fmt.Sprintf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm))
	result.WriteString(fmt.Sprintf("        Issuer: %v\n", NameToString(cert.Issuer)))
	result.WriteString(fmt.Sprintf("        Validity:\n"))
	result.WriteString(fmt.Sprintf("            Not Before: %v\n", cert.NotBefore))
	result.WriteString(fmt.Sprintf("            Not After : %v\n", cert.NotAfter))
	result.WriteString(fmt.Sprintf("        Subject: %v\n", NameToString(cert.Subject)))
	result.WriteString(fmt.Sprintf("        Subject Public Key Info:\n"))
	result.WriteString(fmt.Sprintf("            Public Key Algorithm: %v\n", publicKeyAlgorithmToString(cert.PublicKeyAlgorithm)))
	result.WriteString(fmt.Sprintf("%v\n", publicKeyToString(cert.PublicKeyAlgorithm, cert.PublicKey)))
	/* NOTYET
	if cert.IssuerUniqueId.BitLength > 0 {
		result.WriteString(fmt.Sprintf("        Issuer Unique ID:\n"))
		result.WriteString(fmt.Sprintf("            %v\n", bitStringToString(cert.IssuerUniqueId)))
	}
	if cert.SubjectUniqueId.BitLength > 0 {
		result.WriteString(fmt.Sprintf("        Subject Unique ID:\n"))
		result.WriteString(fmt.Sprintf("            %v\n", bitStringToString(cert.SubjectUniqueId)))
	}
	*/
	var showCritical = func(critical bool) {
		if critical {
			result.WriteString(" critical")
		}
		result.WriteString("\n")
	}
	if len(cert.Extensions) > 0 {
		result.WriteString(fmt.Sprintf("        X509v3 extensions:\n"))
	}
	// First display the extensions that are already cracked out
	count, critical := oidInExtensions(OidExtensionAuthorityKeyId, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Authority Key Identifier:"))
		showCritical(critical)
		result.WriteString(fmt.Sprintf("                keyid:%v\n", hex.EncodeToString(cert.AuthorityKeyId)))
	}
	count, critical = oidInExtensions(OidExtensionSubjectKeyId, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Subject Key Identifier:"))
		showCritical(critical)
		result.WriteString(fmt.Sprintf("                keyid:%v\n", hex.EncodeToString(cert.SubjectKeyId)))
	}
	count, critical = oidInExtensions(OidExtensionKeyUsage, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Key Usage:"))
		showCritical(critical)
		result.WriteString(fmt.Sprintf("                %v\n", keyUsageToString(cert.KeyUsage)))
	}
	count, critical = oidInExtensions(OidExtensionExtendedKeyUsage, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Extended Key Usage:"))
		showCritical(critical)
		var usages bytes.Buffer
		for _, usage := range cert.ExtKeyUsage {
			commaAppend(&usages, extKeyUsageToString(usage))
		}
		for _, oid := range cert.UnknownExtKeyUsage {
			commaAppend(&usages, oid.String())
		}
		result.WriteString(fmt.Sprintf("                %v\n", usages.String()))
	}
	count, critical = oidInExtensions(OidExtensionBasicConstraints, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Basic Constraints:"))
		showCritical(critical)
		result.WriteString(fmt.Sprintf("                CA:%t", cert.IsCA))
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			result.WriteString(fmt.Sprintf(", pathlen:%d", cert.MaxPathLen))
		}
		result.WriteString(fmt.Sprintf("\n"))
	}
	count, critical = oidInExtensions(OidExtensionSubjectAltName, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Subject Alternative Name:"))
		showCritical(critical)
		var buf bytes.Buffer
		for _, name := range cert.DNSNames {
			commaAppend(&buf, "DNS:"+name)
		}
		for _, email := range cert.EmailAddresses {
			commaAppend(&buf, "email:"+email)
		}
		for _, ip := range cert.IPAddresses {
			commaAppend(&buf, "IP Address:"+ip.String())
		}

		result.WriteString(fmt.Sprintf("                %v\n", buf.String()))
		// @@@ doesn't include other name forms
	}

	count, critical = oidInExtensions(OidExtensionNameConstraints, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Name Constraints:"))
		showCritical(critical)
		if len(cert.PermittedDNSDomains) > 0 {
			result.WriteString(fmt.Sprintf("                Permitted:\n"))
			var buf bytes.Buffer
			for _, name := range cert.PermittedDNSDomains {
				commaAppend(&buf, "DNS:"+name)
			}
			result.WriteString(fmt.Sprintf("                  %v\n", buf.String()))
		}
		/* NOTYET
		if len(cert.ExcludedDNSDomains) > 0 {
			result.WriteString(fmt.Sprintf("                Excluded:\n"))
			var buf bytes.Buffer
			for _, name := range cert.ExcludedDNSDomains {
				commaAppend(&buf, "DNS:"+name)
			}
			result.WriteString(fmt.Sprintf("                  %v\n", buf.String()))
		}
		*/
		// @@@ doesn't include other name forms
	}

	count, critical = oidInExtensions(OidExtensionCertificatePolicies, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Certificate Policies:"))
		showCritical(critical)
		for _, oid := range cert.PolicyIdentifiers {
			result.WriteString(fmt.Sprintf("                Policy: %v\n", oid.String()))
			// @@@ no qualifiers if present
		}
	}

	count, critical = oidInExtensions(OidExtensionCRLDistributionPoints, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 CRL Distribution Points:"))
		showCritical(critical)
		result.WriteString(fmt.Sprintf("                Full Name:\n"))
		var buf bytes.Buffer
		for _, pt := range cert.CRLDistributionPoints {
			commaAppend(&buf, "URI:"+pt)
		}
		result.WriteString(fmt.Sprintf("                    %v\n", buf.String()))
		// @@@ No other fields nor types
	}

	count, critical = oidInExtensions(OidExtensionAuthorityInfoAccess, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            Authority Information Access:"))
		showCritical(critical)
		var issuerBuf bytes.Buffer
		for _, issuer := range cert.IssuingCertificateURL {
			commaAppend(&issuerBuf, "URI:"+issuer)
		}
		if issuerBuf.Len() > 0 {
			result.WriteString(fmt.Sprintf("                CA Issuers - %v\n", issuerBuf.String()))
		}
		var ocspBuf bytes.Buffer
		for _, ocsp := range cert.OCSPServer {
			commaAppend(&ocspBuf, "URI:"+ocsp)
		}
		if ocspBuf.Len() > 0 {
			result.WriteString(fmt.Sprintf("                OCSP - %v\n", ocspBuf.String()))
		}
		// @@@ other GeneralName types
	}

	for _, ext := range cert.Extensions {
		// Skip extensions that are already cracked out
		if oidForStandardExtension(ext.Id) {
			continue
		}
		result.WriteString(fmt.Sprintf("            %v:", ext.Id))
		if ext.Critical {
			result.WriteString(fmt.Sprintf(" critical"))
		}
		result.WriteString(fmt.Sprintf("\n"))
	}
	return result.String()
}

var root = flag.String("root", "", "Root CA certificate file")
var intermediate = flag.String("intermediate", "", "Intermediate CA certificate file")
var validate = flag.Bool("validate", false, "Validate certificate signatures")

func addCerts(filename string, pool *x509.CertPool) {
	if filename != "" {
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatalf("Failed to read certificate file: %v\n", err)
		}
		roots, err := x509.ParseCertificates(data)
		if err != nil {
			log.Fatalf("Failed to parse certificate from %s: %v\n", filename, err)
		}
		for _, cert := range roots {
			pool.AddCert(cert)
		}
	}
}

func main() {
	flag.Parse()

	opts := x509.VerifyOptions{
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
	}
	addCerts(*root, opts.Roots)
	addCerts(*intermediate, opts.Intermediates)

	for _, filename := range flag.Args() {
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Failed to read data: %v\n", filename, err)
			continue
		}
		certs, err := x509.ParseCertificates(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Failed to parse data: %v\n", filename, err)
			continue
		}
		for _, cert := range certs {
			fmt.Print(CertificateToString(cert))
			if *validate {
				_, err := cert.Verify(opts)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: Verification error: %v\n", filename, err)
				}
			}
		}
	}
}

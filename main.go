package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func getSha256Fingerprint(certificate *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(certificate.Raw)
}

func getSha1Fingerprint(certificate *x509.Certificate) [sha1.Size]byte {
	return sha1.Sum(certificate.Raw)
}

func downloadFromUrl(url string) int64 {
	tokens := strings.Split(url, "/")
	fileName := tokens[len(tokens)-1]
	fmt.Println("Downloading", url, "to", fileName)

	// TODO: check file existence first with io.IsExist
	output, err := os.Create(fileName)
	if err != nil {
		panic("Error while creating " + fileName)
	}
	defer output.Close()

	response, err := http.Get(url)
	if err != nil {
		panic("Error while downloading " + url)
	}
	defer response.Body.Close()

	n, err := io.Copy(output, response.Body)
	if err != nil {
		panic("Error while downloading " + url)
	}

	return n
	//fmt.Println(n, "bytes downloaded.")
}


func convertBytesToCertificate(certificate []byte) *x509.Certificate {
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return cert
}

func VerifyCertificate(certificate []byte) bool {
	// First, create the set of root certificates.
	// This includes the four (currently valid) DOD Root CAs

	const rootCA5 = `
-----BEGIN CERTIFICATE-----
MIICJDCCAaqgAwIBAgIBDzAKBggqhkjOPQQDAzBbMQswCQYDVQQGEwJVUzEYMBYG
A1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsTA1BL
STEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgNTAeFw0xNjA2MTQxNzE3MjdaFw00MTA2
MTQxNzE3MjdaMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1l
bnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYwFAYDVQQDEw1Eb0QgUm9v
dCBDQSA1MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAENmLeC07Ax9cpRTp/HJnmKiF2
sQDdjEf/wLG0+s46TlL7p+02LRweHJCNl6orpuLTc3N8XBzQZ/QKKdOQhOtR5fFe
HMDShoTFbdEkSQ7sF4nkaMjeGlwaBtA4GTMpARqBo0IwQDAdBgNVHQ4EFgQUhsAV
Qvtxdtw+LRFbIRBENcrB3BQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwMDaAAwZQIwQQbk3t5iNJ3fuKoW2W2iOB85IlfJcIQfkw9X
fgUvpUszzRXqV9XSKx+bjXzOarbMAjEAt4HS4TuTzxFk3AsvF9Jt1dgF5FByYmXc
pDzKYaUGmsn77cQwyXuJ4KW+Y1XmnBHj
-----END CERTIFICATE-----`

	const rootCA4 = `
-----BEGIN CERTIFICATE-----
MIIB6zCCAY+gAwIBAgIBATAMBggqhkjOPQQDAgUAMFsxCzAJBgNVBAYTAlVTMRgw
FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMD
UEtJMRYwFAYDVQQDEw1Eb0QgUm9vdCBDQSA0MB4XDTEyMDczMDE5NDgyM1oXDTMy
MDcyNTE5NDgyM1owWzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu
bWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFjAUBgNVBAMTDURvRCBS
b290IENBIDQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR2yNhDyw8H0iwPKtA4
8YLNQlXn3B1agLcIkUtU1k+yZoU0lo0uPvTgSpF8zM2GnxHgUqFmgsbLkCPsX1/1
8DxFo0IwQDAdBgNVHQ4EFgQUvcG5a030HewwkL9ic8CEM/JxJIUwDgYDVR0PAQH/
BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDAYIKoZIzj0EAwIFAANIADBFAiEA6GGK
99yqCaUH0kSeggNaRFNHhCOZz1zT3kpe1rs1NUYCIHYPuMR8FjV/1BLtiD2AEWtk
B0xFZd9Trl8B7fFD0vW3
-----END CERTIFICATE-----`

	const rootCA3 = `
-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEY
MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsT
A1BLSTEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgMzAeFw0xMjAzMjAxODQ2NDFaFw0y
OTEyMzAxODQ2NDFaMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYwFAYDVQQDEw1Eb0Qg
Um9vdCBDQSAzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqewUcoro
S3Cj2hADhKb7pzYNKjpSFr8wFVKGBUcgz6qmzXXEZG7v8WAjywpmQK60yGgqAFFo
STfpWTJNlbxDJ+lAjToQzhS8Qxih+d7M54V2c14YGiNbvT8f8u2NGcwD0UCkj6cg
AkwnWnk29qM3IY4AWgYWytNVlm8xKbtyDsviSFHy1DekNdZv7hezsQarCxmG6CNt
MRsoeGXF3mJSvMF96+6gXVQE+7LLK7IjVJGCTPC/unRAOwwERYBnXMXrolfDGn8K
Lb1/udzBmbDIB+QMhjaUOiUv8n3mlzwblLSXWQbJOuQL2erp/DtzNG/955jk86HC
kF8c9T8u1xnTfwIDAQABo0IwQDAdBgNVHQ4EFgQUbIqUonexgHIdgXoWqvLczmbu
RcAwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAJ9xpMC2ltKAQ6BI6R92BPnFPK1mGFhjm8O26GiKhVpCZhK00uaLiH+H
9Jj1qMYJyR/wLB/sgrj0pUc4wTMr30x+mr4LC7HLD3xQKBDPio2i6bqshtfUsZNf
Io+WBbRODHWRfdPy55TClBR2T48MqxCHWDKFB3WGEgte6lO0CshMhJIf6+hBhjy6
9E5BStFsWEdBw4Za8u7p8pgnguouNtb4Bl6C8aBSk0QJutKpGVpYo6hdIG1PZPgw
hxuQE0iBzcqQxw3B1Jg/jvIOV2gzEo6ZCbHw5PYQ9DbySb3qozjIVkEjg5rfoRs1
fOs/QbP1b0s6Xq5vk3aY0vGZnUXEjnI=
-----END CERTIFICATE-----`

	const rootCA2 = `
-----BEGIN CERTIFICATE-----
MIIDcDCCAligAwIBAgIBBTANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJVUzEY
MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsT
A1BLSTEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgMjAeFw0wNDEyMTMxNTAwMTBaFw0y
OTEyMDUxNTAwMTBaMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYwFAYDVQQDEw1Eb0Qg
Um9vdCBDQSAyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCzB9o07
rP8/PNZxvrh0IgfscEEV/KtA4weqwcPYn/7aTDq/P8jYKHtLNgHArEUlw9IOCo+F
GGQQPRoTcCpvjtfcjZOzQQ84Ic2tq8I9KgXTVxE3Dc2MUfmT48xGSSGOFLTNyxQ+
OM1yMe6rEvJl6jQuVl3/7mN1y226kTT8nvP0LRy+UMRC31mI/2qz+qhsPctWcXEF
lrufgOWARVlnQbDrw61gpIB1BhecDvRD4JkOG/t/9bPMsoGCsf0ywbi+QaRktWA6
WlEwjM7eQSwZR1xJEGS5dKmHQa99brrBuKG/ZTE6BGf5tbuOkooAY7ix5ow4X4P/
UNU7ol1rshDMYwIDAQABoz8wPTAdBgNVHQ4EFgQUSXS7DF66ev4CVO97oMaVxgmA
cJYwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD
ggEBAJiRjT+JyLv1wGlzKTs1rLqzCHY9cAmS6YREIQF9FHYb7lFsHY0VNy17MWn0
mkS4r0bMNPojywMnGdKDIXUr5+AbmSbchECV6KjSzPZYXGbvP0qXEIIdugqi3VsG
K52nZE7rLgE1pLQ/E61V5NVzqGmbEfGY8jEeb0DU+HifjpGgb3AEkGaqBivO4XqS
tX3h4NGW56E6LcyxnR8FRO2HmdNNGnA5wQQM5X7Z8a/XIA7xInolpHOZzD+kByeW
qKKV7YK5FtOeC4fCwfKI9WLfaN/HvGlR7bFc3FRUKQ8JOZqsA8HbDE2ubwp6Fknx
v5HSOJTT9pUst2zJQraNypCNhdk=
-----END CERTIFICATE-----`

	roots := x509.NewCertPool()
	err5 := roots.AppendCertsFromPEM([]byte(rootCA5))
	err4 := roots.AppendCertsFromPEM([]byte(rootCA4))
	err3 := roots.AppendCertsFromPEM([]byte(rootCA3))
	err2 := roots.AppendCertsFromPEM([]byte(rootCA2))

	if !err5 || !err4 || !err3 || !err2 {
		panic("failed to parse root certificate")
	}

	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil  {
		return false
	} else {
		return true
	}
}

func loadCertificates() [][]byte {

	cert, err := os.Open("DoD_CAs.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemfileinfo, _ := cert.Stat()
	size := pemfileinfo.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(cert)
	_, err = buffer.Read(pembytes)
	certString := string(pembytes)
	concatcerts := strings.SplitAfter(certString, "-----END CERTIFICATE-----")
	var certs [][]byte
	for _, s := range concatcerts {
		cert := strings.Split(s, "\n")
		var tempString string
		for _, c := range cert {
			if strings.HasPrefix(c, "subject") || strings.HasPrefix(c, "issuer") || c == "" {

			} else {
				tempString += c
				tempString += "\n"
			}
		}
		certBytes := []byte(tempString)
		certs = append(certs, certBytes)
		tempString = ""
	}
	cert.Close()
	return certs
}

func main() {


	//var hashes []string
	certs := loadCertificates()
	downloadCRLs()


	for _, k := range certs {
		if len(k) > 0 && VerifyCertificate(k) {
			cert := convertBytesToCertificate(k)
			if strings.HasPrefix(cert.Subject.CommonName, "DoD Root") || true{
				fingerprint := getSha256Fingerprint(cert)
				var crlSize int64 = 0
				if len(cert.CRLDistributionPoints) > 0 {
					crlSize = downloadFromUrl(cert.CRLDistributionPoints[0])
				} else {
					crlSize = 0
				}
				s:= cert.Subject.CommonName + " " + cert.SignatureAlgorithm.String() + " Issuing CA: "+ cert.Issuer.CommonName + " CRL Size: " + strconv.Itoa(int(crlSize)) + ": "
				s += fmt.Sprintf("%x", fingerprint)
				//hashes = append(hashes, s)
				fmt.Println(s)
			}
		}
	}


}

func downloadCRLs() {
	certs := loadCertificates()

	for _, k := range certs {
		if len(k) > 0 && VerifyCertificate(k) {
			cert := convertBytesToCertificate(k)
			if !strings.HasPrefix(cert.Subject.CommonName, "DoD Root") {
				var crl string = ""
				if strings.HasPrefix(cert.Subject.CommonName, "DOD EMAIL") {
					crl = "http://crl.disa.mil/crl/DODEMAILCA_" + strings.SplitAfter(cert.Subject.CommonName, "-")[1] + ".crl"
				} else if strings.HasPrefix(cert.Subject.CommonName, "DOD ID SW") {
					crl = "http://crl.disa.mil/crl/DODIDSWCA_" + strings.SplitAfter(cert.Subject.CommonName, "-")[1] + ".crl"
				} else if strings.HasPrefix(cert.Subject.CommonName, "DOD ID") {
					crl = "http://crl.disa.mil/crl/DODIDCA_" + strings.SplitAfter(cert.Subject.CommonName, "-")[1] + ".crl"
				} else if strings.HasPrefix(cert.Subject.CommonName, "DOD SW") {
					crl = "http://crl.disa.mil/crl/DODSWCA_" + strings.SplitAfter(cert.Subject.CommonName, "-")[1] + ".crl"
				} else {
					continue
				}
				fingerprint := getSha256Fingerprint(cert)
				var crlSize int64 = 0
				crlSize = downloadFromUrl(crl)
				s := cert.Subject.CommonName + " " + cert.SignatureAlgorithm.String() + " Issuing CA: " + cert.Issuer.CommonName + " CRL Size: " + strconv.Itoa(int(crlSize)) + ": "
				s += fmt.Sprintf("%x", fingerprint)
				//hashes = append(hashes, s)
				fmt.Println(s)
			}
		}
	}

}

func CreateSmartCardPlist(hashes []string, filename string) string {

	base := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>TrustedAuthorities</key>
	<array>`

	for _, k:= range hashes  {
		base += "/n" + "<string>" + k + "</string>" + "\n"

	}
	base += `</array>\n`
	base += `	<key>AttributeMapping</key>
	<dict>
		<key>fields</key>
		<array>
			<string>NT Principal Name</string>
		</array>
		<key>formatString</key>
		<string>Kerberos:$1</string>
		<key>dsAttributeString</key>
		<string>dsAttrTypeStandard:AltSecurityIdentities</string>
	</dict>
</dict>
</plist>`
return base

}

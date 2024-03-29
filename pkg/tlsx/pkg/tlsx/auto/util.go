package auto

import (
	"github.com/homelanmder/synScanner/pkg/tlsx/pkg/tlsx/openssl"
	"github.com/homelanmder/synScanner/pkg/tlsx/pkg/tlsx/tls"
	"github.com/homelanmder/synScanner/pkg/tlsx/pkg/tlsx/ztls"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

var (
	allCiphersNames      []string
	supportedTlsVersions []string
)

func init() {
	allCiphersNames = append(tls.AllCiphersNames, ztls.AllCiphersNames...)
	allCiphersNames = append(allCiphersNames, openssl.AllCiphersNames...)
	supportedTlsVersions = append(tls.SupportedTlsVersions, ztls.SupportedTlsVersions...)
	supportedTlsVersions = append(supportedTlsVersions, openssl.SupportedTLSVersions...)
	allCiphersNames = sliceutil.Dedupe(allCiphersNames)
	supportedTlsVersions = sliceutil.Dedupe(supportedTlsVersions)
}

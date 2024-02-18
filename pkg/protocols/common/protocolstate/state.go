package protocolstate

import (
	"github.com/homelanmder/synScanner/pkg/fastdialer/fastdialer"
)

// Dialer is a shared fastdialer instance for host DNS resolution
var Dialer *fastdialer.Dialer

//
//// Init creates the Dialer instance based on user configuration
//func Init(options *types.Options) error {
//
//	opts := fastdialer.DefaultOptions
//	opts.WithDialerHistory = true
//	opts.WithZTLS = options.ZTLS
//	opts.SNIName = options.SNI
//	dialer, err := fastdialer.NewDialer(opts)
//	if err != nil {
//		return errors.Wrap(err, "could not create dialer")
//	}
//	Dialer = dialer
//	return nil
//}

func GetDialer() (*fastdialer.Dialer, error) {
	opts := fastdialer.DefaultOptions
	opts.MaxRetries = 2
	return fastdialer.NewDialer(opts)
}

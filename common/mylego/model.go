package mylego

type CertConfig struct {
	CertMode         string            `mapstructure:"CertMode"` // none, file, http, dns
	CertDomain       string            `mapstructure:"CertDomain"`
	CertFile         string            `mapstructure:"CertFile"`
	KeyFile          string            `mapstructure:"KeyFile"`
	CertContent      string            `mapstructure:"CertContent"`
	KeyContent       string            `mapstructure:"KeyContent"`
	Provider         string            `mapstructure:"Provider"` // alidns, cloudflare, gandi, godaddy....
	Email            string            `mapstructure:"Email"`
	DNSEnv           map[string]string `mapstructure:"DNSEnv"`
	RejectUnknownSni bool              `mapstructure:"RejectUnknownSni"`
}

type LegoCMD struct {
	C    *CertConfig
	path string
}

package config

type Root struct {
	Server      Server      `mapstructure:"server"`
	Database    Database    `mapstructure:"database"`
	AccessToken AccessToken `mapstructure:"access-token"`
	LogPath     LogPath     `mapstructure:"log-path"`
}

type Database struct {
	Redis Redis `mapstructure:"redis"`
	Tls   Tls   `mapstructure:"tls"`
}

type Tls struct {
	Enable             bool   `mapstructure:"enable"`
	CertificateFile    string `mapstructure:"certificate-file"`
	CertificateKeyFile string `mapstructure:"certificate-key-file"`
}

type LogPath struct {
	Error       string `mapstructure:"error"`
	Request     string `mapstructure:"request"`
	Transaction string `mapstructure:"transaction"`
}

type Redis struct {
	Address       string `mapstructure:"address"`
	Password      string `mapstructure:"password"`
	AccessTokenDB int    `mapstructure:"access-token-db"`
	ClientDB      int    `mapstructure:"client-db"`
	UserDB        int    `mapstructure:"user-db"`
}

type Server struct {
	Address string `mapstructure:"address"`
}

type AccessToken struct {
	TTL         uint `mapstructure:"time-to-live"`
	TTLExpired  uint `mapstructure:"ttl-after-expire"`
	TokenLength uint `mapstructure:"token-length"`
}

package config

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server      ServerConfig          `yaml:"server"`
	Database    DatabaseConfig        `yaml:"database"`
	Telegram    TelegramConfig        `yaml:"telegram"`
	Admin       AdminConfig           `yaml:"admin"`
	SiteSig     string                `yaml:"site_sig"`
	VerifyURL   string                `yaml:"verify_url"`
	SignServers map[string]string     `yaml:"sign_servers"`
	RCSM        RCSMConfig            `yaml:"rcsm"`
	Certs       map[string]CertConfig `yaml:"certs"`
	RSA         RSAConfig             `yaml:"rsa"`
}

type ServerConfig struct {
	Port int `yaml:"port"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
}

type TelegramConfig struct {
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

type AdminConfig struct {
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	JWTSecret string `yaml:"jwt_secret"`
}

type RCSMConfig struct {
	Secrets map[string]string            `yaml:"secrets"`
	URLs    map[string]map[string]string `yaml:"urls"`
}

type CertConfig struct {
	Version int64  `yaml:"version"`
	Cert    string `yaml:"cert"`
}

type RSAConfig struct {
	PublicKey  string `yaml:"public_key"`
	PrivateKey string `yaml:"private_key"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Override with environment variables if they exist
	if port := os.Getenv("PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cfg.Server.Port = p
		}
	}

	if host := os.Getenv("DATABASE_HOST"); host != "" {
		cfg.Database.Host = host
	}

	if port := os.Getenv("DATABASE_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cfg.Database.Port = p
		}
	}

	if user := os.Getenv("DATABASE_USER"); user != "" {
		cfg.Database.User = user
	}

	if password := os.Getenv("DATABASE_PASSWORD"); password != "" {
		cfg.Database.Password = password
	}

	if dbname := os.Getenv("DATABASE_NAME"); dbname != "" {
		cfg.Database.DBName = dbname
	}

	if username := os.Getenv("ADMIN_USERNAME"); username != "" {
		cfg.Admin.Username = username
	}

	if password := os.Getenv("ADMIN_PASSWORD"); password != "" {
		cfg.Admin.Password = password
	}

	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		cfg.Admin.JWTSecret = secret
	}

	return &cfg, nil
}

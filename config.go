package internal

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Name string `yaml:"name"`
	}

	Database struct {
		Host string
		Port int
		User string
		Password string
		Name string
	}

	Admin struct {
		Username string
		Password string
	}

	JWTSecret string
}

func LoadConfig() (*Config, error) {

	cfg := &Config{}

	file, err := os.ReadFile("config/config.yaml")
	if err == nil {
		yaml.Unmarshal(file, cfg)
	}

	cfg.Database.Host = os.Getenv("DATABASE_HOST")
	cfg.Database.User = os.Getenv("DATABASE_USER")
	cfg.Database.Password = os.Getenv("DATABASE_PASSWORD")
	cfg.Database.Name = os.Getenv("DATABASE_NAME")

	port, _ := strconv.Atoi(os.Getenv("DATABASE_PORT"))
	cfg.Database.Port = port

	cfg.Admin.Password = os.Getenv("ADMIN_PASSWORD")
	cfg.JWTSecret = os.Getenv("JWT_SECRET")

	return cfg, nil
}

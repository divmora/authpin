package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Mode        string            `yaml:"mode"` // "standalone" or "multi_tenant"
	Storage     StorageConfig     `yaml:"storage"`
	Security    SecurityConfig    `yaml:"security"`
	RateLimits  RateLimitsConfig  `yaml:"rate_limits"`
	Dispatchers DispatchersConfig `yaml:"dispatchers"`
}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type StorageConfig struct {
	Driver   string         `yaml:"driver"` // "postgres", "dynamodb", "mysql", "memory"
	Postgres PostgresConfig `yaml:"postgres"`
	DynamoDB DynamoDBConfig `yaml:"dynamodb"`
	MySQL    MySQLConfig    `yaml:"mysql"`
}

type PostgresConfig struct {
	DSN            string `yaml:"dsn"`
	MaxConnections int32  `yaml:"max_connections"`
	MinConnections int32  `yaml:"min_connections"`
}

type DynamoDBConfig struct {
	Region    string `yaml:"region"`
	TableName string `yaml:"table_name"`
	Endpoint  string `yaml:"endpoint"`
}

type MySQLConfig struct {
	DSN            string `yaml:"dsn"`
	MaxConnections int32  `yaml:"max_connections"`
}

type SecurityConfig struct {
	MasterKey         string `yaml:"master_key"`
	HashAlgorithm     string `yaml:"hash_algorithm"`
	JWTPrivateKey     string `yaml:"jwt_private_key"`
	DefaultTTLSeconds int    `yaml:"default_ttl_seconds"`
	MaxAttempts       int    `yaml:"max_attempts"`
	OTPLength         int    `yaml:"otp_length"`
}

type RateLimitsConfig struct {
	PerRecipientMaxPerHour int `yaml:"per_recipient_max_per_hour"`
	PerIPMaxPerMinute      int `yaml:"per_ip_max_per_minute"`
	PerTenantMaxPerMinute  int `yaml:"per_tenant_max_per_minute"`
}

type DispatchersConfig struct {
	Email EmailConfig `yaml:"email"`
	SMS   SMSConfig   `yaml:"sms"`
}

type EmailConfig struct {
	Provider string     `yaml:"provider"` // "smtp", "ses", "mock"
	From     string     `yaml:"from"`
	FromName string     `yaml:"from_name"`
	SMTP     SMTPConfig `yaml:"smtp"`
}

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	UseTLS   bool   `yaml:"use_tls"`
}

type SMSConfig struct {
	Provider string       `yaml:"provider"` // "twilio", "sns", "mock"
	Twilio   TwilioConfig `yaml:"twilio"`
}

type TwilioConfig struct {
	AccountSID string `yaml:"account_sid"`
	AuthToken  string `yaml:"auth_token"`
	FromPhone  string `yaml:"from_phone"`
}

// Load reads configuration from file and applies environment overrides.
func Load(path string) (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Mode: "standalone",
		Storage: StorageConfig{
			Driver: "postgres",
		},
		Security: SecurityConfig{
			MasterKey:         "default-insecure-32-byte-change-me!",
			DefaultTTLSeconds: 300,
			MaxAttempts:       3,
			OTPLength:         6,
		},
		Dispatchers: DispatchersConfig{
			Email: EmailConfig{
				Provider: "mock",
				From:     "noreply@authpin.local",
				FromName: "AuthPin",
			},
			SMS: SMSConfig{
				Provider: "mock",
			},
		},
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// Environment variable overrides
	if portStr := os.Getenv("PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			cfg.Server.Port = p
		}
	}
	if host := os.Getenv("HOST"); host != "" {
		cfg.Server.Host = host
	}
	if mode := os.Getenv("AUTHPIN_MODE"); mode != "" {
		cfg.Mode = mode
	}
	if driver := os.Getenv("DATABASE_DRIVER"); driver != "" {
		cfg.Storage.Driver = driver
	}
	if pgDSN := os.Getenv("POSTGRES_DSN"); pgDSN != "" {
		cfg.Storage.Postgres.DSN = pgDSN
	} else if pgDSN := os.Getenv("DATABASE_URL"); pgDSN != "" {
		cfg.Storage.Postgres.DSN = pgDSN
	}
	if mysqlDSN := os.Getenv("MYSQL_DSN"); mysqlDSN != "" {
		cfg.Storage.MySQL.DSN = mysqlDSN
	}
	if dynamoRegion := os.Getenv("AWS_REGION"); dynamoRegion != "" {
		cfg.Storage.DynamoDB.Region = dynamoRegion
	} else if dynamoRegion := os.Getenv("DYNAMODB_REGION"); dynamoRegion != "" {
		cfg.Storage.DynamoDB.Region = dynamoRegion
	}
	if dynamoTable := os.Getenv("DYNAMODB_TABLE"); dynamoTable != "" {
		cfg.Storage.DynamoDB.TableName = dynamoTable
	}
	if dynamoEndpoint := os.Getenv("DYNAMODB_ENDPOINT"); dynamoEndpoint != "" {
		cfg.Storage.DynamoDB.Endpoint = dynamoEndpoint
	}
	if key := os.Getenv("MASTER_KEY"); key != "" {
		cfg.Security.MasterKey = key
	}

	return cfg, nil
}

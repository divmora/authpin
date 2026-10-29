package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/divmora/authpin/internal/api"
	"github.com/divmora/authpin/internal/config"
	"github.com/divmora/authpin/internal/crypto"
	"github.com/divmora/authpin/internal/dispatcher"
	"github.com/divmora/authpin/internal/model"
	"github.com/divmora/authpin/internal/service"
	"github.com/divmora/authpin/internal/storage"
	"github.com/divmora/authpin/internal/storage/dynamodb"
	"github.com/divmora/authpin/internal/storage/memory"
	"github.com/divmora/authpin/internal/storage/mysql"
	"github.com/divmora/authpin/internal/storage/postgres"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to YAML configuration file")
	portFlag := flag.Int("port", 0, "Port override")
	driverFlag := flag.String("driver", "", "Storage driver override (postgres, memory)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	if *portFlag > 0 {
		cfg.Server.Port = *portFlag
	}
	if *driverFlag != "" {
		cfg.Storage.Driver = *driverFlag
	}

	log.Printf("[INIT] Starting AuthPin service on %s:%d (mode: %s, storage: %s)",
		cfg.Server.Host, cfg.Server.Port, cfg.Mode, cfg.Storage.Driver)

	// 1. Initialize Cryptographic Vault
	vault, err := crypto.NewVault(cfg.Security.MasterKey, cfg.Security.JWTPrivateKey)
	if err != nil {
		log.Fatalf("failed to initialize crypto vault: %v", err)
	}

	// 2. Initialize Pluggable Storage Engine
	var store storage.StorageEngine
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch cfg.Storage.Driver {
	case "postgres":
		if cfg.Storage.Postgres.DSN == "" {
			log.Printf("[WARN] No postgres DSN configured. Falling back to in-memory storage engine for local run.")
			store = memory.New()
		} else {
			pgStore, err := postgres.New(ctx, cfg.Storage.Postgres.DSN, cfg.Storage.Postgres.MaxConnections)
			if err != nil {
				log.Fatalf("failed to connect to PostgreSQL: %v", err)
			}
			store = pgStore
			log.Printf("[INIT] Connected to PostgreSQL storage engine.")
		}
	case "mysql":
		if cfg.Storage.MySQL.DSN == "" {
			log.Printf("[WARN] No MySQL DSN configured. Falling back to in-memory storage engine for local run.")
			store = memory.New()
		} else {
			myStore, err := mysql.New(ctx, cfg.Storage.MySQL.DSN, cfg.Storage.MySQL.MaxConnections)
			if err != nil {
				log.Fatalf("failed to connect to MySQL: %v", err)
			}
			store = myStore
			log.Printf("[INIT] Connected to MySQL storage engine.")
		}
	case "dynamodb":
		dynamoStore, err := dynamodb.New(ctx, dynamodb.Config{
			Region:    cfg.Storage.DynamoDB.Region,
			TableName: cfg.Storage.DynamoDB.TableName,
			Endpoint:  cfg.Storage.DynamoDB.Endpoint,
		})
		if err != nil {
			log.Fatalf("failed to connect to AWS DynamoDB: %v", err)
		}
		store = dynamoStore
		log.Printf("[INIT] Connected to AWS DynamoDB storage engine (%s, table: %s).", cfg.Storage.DynamoDB.Region, cfg.Storage.DynamoDB.TableName)
	default:
		log.Printf("[INIT] Using in-memory storage engine.")
		store = memory.New()
	}
	defer store.Close()

	// 3. Initialize Dispatchers
	var emailDisp dispatcher.Dispatcher
	if cfg.Dispatchers.Email.Provider == "smtp" && cfg.Dispatchers.Email.SMTP.Host != "" {
		emailDisp = dispatcher.NewSMTPDispatcher(dispatcher.SMTPConfig{
			Host:     cfg.Dispatchers.Email.SMTP.Host,
			Port:     cfg.Dispatchers.Email.SMTP.Port,
			Username: cfg.Dispatchers.Email.SMTP.Username,
			Password: cfg.Dispatchers.Email.SMTP.Password,
			From:     cfg.Dispatchers.Email.From,
			FromName: cfg.Dispatchers.Email.FromName,
			UseTLS:   cfg.Dispatchers.Email.SMTP.UseTLS,
		})
		log.Printf("[INIT] Initialized SMTP email dispatcher (%s)", cfg.Dispatchers.Email.From)
	} else {
		emailDisp = dispatcher.NewMockDispatcher(model.ChannelEmail)
		log.Printf("[INIT] Initialized Mock email dispatcher")
	}

	var smsDisp dispatcher.Dispatcher
	if cfg.Dispatchers.SMS.Provider == "twilio" && cfg.Dispatchers.SMS.Twilio.AccountSID != "" {
		smsDisp = dispatcher.NewTwilioDispatcher(dispatcher.TwilioConfig{
			AccountSID: cfg.Dispatchers.SMS.Twilio.AccountSID,
			AuthToken:  cfg.Dispatchers.SMS.Twilio.AuthToken,
			FromPhone:  cfg.Dispatchers.SMS.Twilio.FromPhone,
		})
		log.Printf("[INIT] Initialized Twilio SMS dispatcher")
	} else {
		smsDisp = dispatcher.NewMockDispatcher(model.ChannelSMS)
		log.Printf("[INIT] Initialized Mock SMS dispatcher")
	}

	routerDisp := dispatcher.NewRouter(emailDisp, smsDisp)

	// 4. Initialize Core Service
	otpSvc := service.NewOTPService(service.Config{
		DefaultTTLSeconds: cfg.Security.DefaultTTLSeconds,
		DefaultDigits:     cfg.Security.OTPLength,
		DefaultMaxRetries: cfg.Security.MaxAttempts,
		IssuerName:        "AuthPin",
	}, store, vault, routerDisp)

	// 5. Background Cleanup Worker
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()

	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupCtx.Done():
				return
			case <-ticker.C:
				purged, err := store.CleanupExpired(context.Background(), time.Now().UTC(), 500)
				if err == nil && purged > 0 {
					log.Printf("[WORKER] Purged %d expired OTP sessions", purged)
				}
			}
		}
	}()

	// 6. HTTP Server Setup
	handler := api.NewHandler(otpSvc, store)
	httpHandler := api.NewRouter(api.RouterConfig{
		IsMultiTenant: cfg.Mode == "multi_tenant",
		APIKeys:       map[string]string{},
	}, handler)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      httpHandler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// 7. Graceful Shutdown Listener
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[READY] AuthPin HTTP server listening on http://%s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
	}()

	<-stop
	log.Printf("[SHUTDOWN] Signal received, shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERROR] Server forced to shutdown: %v", err)
	}

	log.Printf("[SHUTDOWN] AuthPin stopped cleanly.")
}

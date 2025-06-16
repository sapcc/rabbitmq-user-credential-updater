package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	rabbithole "github.com/michaelklishin/rabbit-hole/v3"
	"github.com/rabbitmq/default-user-credential-updater/updater"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/ini.v1"
)

func main() {
	var managementURI, caFile, adminFile, watchDir string

	flag.StringVar(
		&adminFile,
		"admin-file",
		"/var/lib/rabbitmq/.rabbitmqadmin.conf",
		"Absolute path to file used by rabbitmqadmin CLI. "+
			"It contains RabbitMQ admin username (must be the same as default user username) and (old) password.")
	flag.StringVar(
		&watchDir,
		"watch-dir",
		"/etc/rabbitmq/secrets",
		"Directory containing user secrets files in the format user_<id>_{username,password,tag}.")
	flag.StringVar(
		&managementURI,
		"management-uri",
		"http://127.0.0.1:15672",
		"RabbitMQ Management URI")
	flag.StringVar(
		&caFile,
		"ca-file",
		"/etc/rabbitmq-tls/ca.crt",
		"This file contains the trusted certificate for RabbitMQ server authentication.")
	flag.Parse()

	log := initLogging().WithName("password-updater")

	rabbitAuthClient, err := newRabbitClient(log, managementURI, caFile)
	if err != nil {
		log.Error(err, "failed to create RabbitMQ auth client")
		return
	}
	rabbitAdminClient, err := newRabbitClient(log, managementURI, caFile)
	if err != nil {
		log.Error(err, "failed to create RabbitMQ admin client")
		return
	}

	// Remove trailing new line (.rabbitmqadmin.conf has only one section).
	ini.PrettySection = false

	// This channel will contain a value when the Pod gets terminated.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	// This channel will contain a value when our program terminates itself.
	// This is preferred over calling os.Exit() because os.Exit() does not run deferred functions.
	done := make(chan bool, 1)

	passwordUpdater, err := updater.NewPasswordUpdater(adminFile, watchDir, done, log, rabbitAuthClient, rabbitAdminClient)
	if err != nil {
		log.Error(err, "Failed to initialize PasswordUpdater")
		return
	}

	go passwordUpdater.HandleEvents()

	select {
	case sig := <-sigs:
		log.V(1).Info("terminating", "signal", sig.String())
	case <-done:
		log.V(1).Info("terminating")
	}
}

func initLogging() logr.Logger {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
	cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	cfg.DisableStacktrace = true
	zapLogger, err := cfg.Build()
	if err != nil {
		panic("failed to initialize zap logger: " + err.Error())
	}
	return zapr.NewLogger(zapLogger)
}

func newRabbitClient(log logr.Logger, managementURI, caFile string) (updater.RabbitClient, error) {
	if strings.HasPrefix(managementURI, "https") {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			log.Error(err, "failed to read CA file", "file", caFile)
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig := &tls.Config{
			RootCAs: caCertPool,
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		rmqc, err := rabbithole.NewTLSClient(managementURI, "", "", transport)
		if err != nil {
			log.Error(err, "failed to create rabbithole TLS client", "uri", managementURI, "ca-file", caFile)
			return nil, err
		}
		return rabbitHoleClientWrapper{rmqc}, nil
	}
	rmqc, err := rabbithole.NewClient(managementURI, "", "")
	if err != nil {
		log.Error(err, "failed to create rabbithole client", "uri", managementURI)
		return nil, err
	}
	return rabbitHoleClientWrapper{rmqc}, nil
}

type rabbitHoleClientWrapper struct {
	rabbitHoleClient *rabbithole.Client
}

func (w rabbitHoleClientWrapper) GetUser(username string) (*rabbithole.UserInfo, error) {
	return w.rabbitHoleClient.GetUser(username)
}
func (w rabbitHoleClientWrapper) PutUser(username string, info rabbithole.UserSettings) (*http.Response, error) {
	return w.rabbitHoleClient.PutUser(username, info)
}
func (w rabbitHoleClientWrapper) Whoami() (*rabbithole.WhoamiInfo, error) {
	return w.rabbitHoleClient.Whoami()
}
func (w rabbitHoleClientWrapper) UpdatePermissionsIn(vhost string, username string, permissions rabbithole.Permissions) (*http.Response, error) {
	return w.rabbitHoleClient.UpdatePermissionsIn(vhost, username, permissions)
}
func (w rabbitHoleClientWrapper) GetUsername() string {
	return w.rabbitHoleClient.Username
}
func (w rabbitHoleClientWrapper) SetUsername(username string) {
	w.rabbitHoleClient.Username = username
}
func (w rabbitHoleClientWrapper) SetPassword(passwd string) {
	w.rabbitHoleClient.Password = passwd
}

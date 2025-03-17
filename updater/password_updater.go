package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
)

// NewPasswordUpdater creates a new instance of PasswordUpdater with a properly
// initialized CredentialState and file system watcher.
func NewPasswordUpdater(adminFile string, watchDir string, done chan<- bool, log logr.Logger, adminClient RabbitClient, authClient RabbitClient) (*PasswordUpdater, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	log.V(1).Info("start watching", "directory", watchDir)
	if err := watcher.Add(watchDir); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to add directory %q to watcher: %w", watchDir, err)
	}

	credentialState, err := loadSecrets(watchDir, log)
	if err != nil {
		return nil, fmt.Errorf("failed to load credential state: %w", err)
	}
	credentialSpec := make(map[string]UserCredentials)

	return &PasswordUpdater{
		AdminFile:       adminFile,
		WatchDir:        watchDir,
		Watcher:         watcher,
		Done:            done,
		Log:             log,
		adminClient:     adminClient,
		authClient:      authClient,
		CredentialState: credentialState,
		CredentialSpec:  credentialSpec,
	}, nil
}

// loadSecrets scans the watch directory and loads existing credential files
// into a map keyed by userID.
func loadSecrets(watchDir string, log logr.Logger) (map[string]UserCredentials, error) {
	credentialState := make(map[string]UserCredentials)
	files, err := os.ReadDir(watchDir)
	if err != nil {
		log.Error(err, "failed to read watch directory", "watchDir", watchDir)
		return nil, fmt.Errorf("failed to read watch directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), userFilePrefix) {
			continue
		}

		name := file.Name()
		remainder := name[len(userFilePrefix):]
		parts := strings.SplitN(remainder, "_", 2)
		if len(parts) != 2 {
			log.V(1).Info("ignoring file with unexpected name format", "file", name)
			continue
		}

		userID, key := parts[0], parts[1]
		content, err := os.ReadFile(filepath.Join(watchDir, name))
		if err != nil {
			log.Error(err, "failed to read secret file", "file", name)
			continue
		}

		value := strings.TrimSpace(string(content))
		cred := credentialState[userID]
		switch key {
		case "username":
			cred.Username = value
		case "password":
			cred.Password = value
		case "tag":
			if value != "" {
				cred.Tag = value
			} else {
				cred.Tag = ""
			}
		default:
			log.V(1).Info("ignoring unknown credential key", "file", name, "key", key)
			continue
		}
		credentialState[userID] = cred

		if cred.Username != "" && cred.Password != "" {
			log.V(2).Info("loaded credential", "userID", userID, "username", cred.Username)
		}
	}

	for userID, cred := range credentialState {
		if cred.Username == "" || cred.Password == "" {
			if userID == adminUserID {
				return nil, fmt.Errorf("incomplete credentials during load, missing username or password for admin user")
			} else {
				log.V(1).Info("incomplete credentials during initialization",
					"userID", userID,
					"hasUsername", cred.Username != "",
					"hasPassword", cred.Password != "")
			}
		}
	}

	return credentialState, nil
}

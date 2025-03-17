package updater_test

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	rabbithole "github.com/michaelklishin/rabbit-hole/v3"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/rabbitmq/default-user-credential-updater/updater"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/ini.v1"
)

const (
	testWatchDir = "test/secrets"

	testAdminFile        = "test/rabbitmqadmin.conf"
	adminFileSection     = "default"
	adminFileUserKey     = "username"
	adminFilePasswordKey = "password"

	adminUsernameFile = "user_admin_username"
	adminPasswordFile = "user_admin_password"
	adminTagFile      = "user_admin_tag"

	defaultUsernameFile = "user_default_username"
	defaultPasswordFile = "user_default_password"
	defaultTagFile      = "user_default_tag"
)

var _ = Describe("EventHandler", func() {
	var (
		u               *PasswordUpdater
		fakeAuthClient  *fakeRabbitClient
		fakeAdminClient *fakeRabbitClient
		done            chan bool
		// as returned in https://github.com/michaelklishin/rabbit-hole/blob/1de83b96b8ba1e29afd003143a9d8a8234d4e913/client.go#L153
		errUnauthorized = errors.New("Error: API responded with a 401 Unauthorized")
	)

	BeforeEach(func() {
		initConfigFiles()

		log := initLogging()
		fakeAuthClient = &fakeRabbitClient{
			getUserReturn: map[string]getUserReturn{
				"admin": {
					userInfo: &rabbithole.UserInfo{
						HashingAlgorithm: "adminalgo",
						Tags:             rabbithole.UserTags{"administrator"},
					},
				},
				"default": {
					userInfo: &rabbithole.UserInfo{
						HashingAlgorithm: "myalgo",
						Tags:             rabbithole.UserTags{"mytag"},
					},
				},
			},
			// Default: simulate authentication failure so that a PUT is performed when updating default user.
			whoamiReturn: whoamiReturn{err: errors.New("auth failed")},
			putUserReturn: putUserReturn{
				resp: &http.Response{Status: "204 No Content"},
			},
		}

		fakeAdminClient = &fakeRabbitClient{
			getUserReturn: map[string]getUserReturn{
				"admin": {
					userInfo: &rabbithole.UserInfo{
						HashingAlgorithm: "adminalgo",
						Tags:             rabbithole.UserTags{"administrator"},
					},
				},
				"default": {
					userInfo: &rabbithole.UserInfo{
						HashingAlgorithm: "myalgo",
						Tags:             rabbithole.UserTags{"mytag"},
					},
				},
			},
			// For admin updates the authentication is done via fakeAuthClient.
			putUserReturn: putUserReturn{
				resp: &http.Response{Status: "204 No Content"},
			},
		}

		watcher, err := fsnotify.NewWatcher()
		Expect(err).ToNot(HaveOccurred())
		Expect(watcher.Add(testWatchDir)).To(Succeed())
		done = make(chan bool, 1)
		u, err = NewPasswordUpdater(testAdminFile, testWatchDir, done, log, fakeAdminClient, fakeAuthClient)
		Expect(err).NotTo(HaveOccurred())
		go u.HandleEvents()

		// Track method invocations
		DeferCleanup(func() {
			fakeAuthClient.Reset()
			fakeAdminClient.Reset()
		})
	})

	AfterEach(func() {
		u.Watcher.Close()
		initConfigFiles()
	})

	When("a secret file is invalid", func() {
		BeforeEach(func() {
			// Write an empty admin password and trigger a file event.
			err := os.WriteFile(filepath.Join(testWatchDir, adminPasswordFile), []byte(""), 0644)
			Expect(err).NotTo(HaveOccurred())
			now := time.Now()
			err = os.Chtimes(filepath.Join(testWatchDir, adminPasswordFile), now, now)
			Expect(err).NotTo(HaveOccurred())
		})
		It("exits", func() {
			Eventually(done).Should(Receive(), "Should exit when admin password is empty")
		})
	})

	When("passwords already match in credentials state and secrets directory", func() {
		BeforeEach(func() {
			// Pre-populate the state so that no update should occur.
			u.CredentialState = map[string]UserCredentials{
				"default": {
					Username: "default",
					Password: "pwd1",
					Tag:      "mytag",
				},
				"admin": {
					Username: "admin",
					Password: "pwd1",
					Tag:      "administrator",
				},
			}
			// Set the fake client's admin username to simulate that admin is already configured.
			fakeAdminClient.Username = "admin"
			fakeAuthClient.whoamiReturn = whoamiReturn{err: nil} // simulate that auth works (so no PUT is needed)
			// Trigger update without changing the password.
			write(defaultPasswordFile, "pwd1")
		})
		It("does not update RabbitMQ", func() {
			Eventually(fakeAdminClient.PutUserCallCount).Should(BeZero())
		})
	})

	When("default user password updates", func() {
		JustBeforeEach(func() {
			write(defaultPasswordFile, "pwd2")
		})
		When("default user password in RabbitMQ is not yet up-to-date", func() {
			BeforeEach(func() {
				// Ensure that the authentication fails so that the update will be triggered.
				fakeAuthClient.whoamiReturn = whoamiReturn{err: errUnauthorized}
				fakeAuthClient.getUserReturn["default"] = getUserReturn{
					userInfo: &rabbithole.UserInfo{
						HashingAlgorithm: "myalgo",
						Tags:             rabbithole.UserTags{"mytag"},
					},
				}
				fakeAdminClient.getUserReturn["default"] = getUserReturn{
					userInfo: &rabbithole.UserInfo{
						HashingAlgorithm: "myalgo",
						Tags:             rabbithole.UserTags{"mytag"},
					},
				}
				fakeAdminClient.putUserReturn = putUserReturn{
					resp: &http.Response{
						Status: "204 No Content",
					},
				}
			})
			It("updates the default user password in RabbitMQ", func() {
				Eventually(func() int {
					return len(fakeAdminClient.PutUserCalls)
				}).Should(Equal(1))

				expectedUserSettings := rabbithole.UserSettings{
					Name:             "default",
					Tags:             rabbithole.UserTags{"mytag"},
					Password:         "pwd2",
					HashingAlgorithm: "myalgo",
				}

				Expect(fakeAdminClient.PutUserCalls[0].Settings).To(Equal(expectedUserSettings))
			})
		})
		When("default user password in RabbitMQ is up-to-date", func() {
			BeforeEach(func() {
				// Simulate that authentication works (the new password is already in effect).
				fakeAuthClient.whoamiReturn = whoamiReturn{err: nil}
				// Even if the GET /api/users/default is performed, the authenticate call will succeed.
				fakeAuthClient.getUserReturn["default"] = getUserReturn{
					userInfo: &rabbithole.UserInfo{
						HashingAlgorithm: "myalgo",
						Tags:             rabbithole.UserTags{"mytag"},
					},
				}
			})
			Context("before GET /api/users/default", func() {
				BeforeEach(func() {
					fakeAuthClient.getUserReturn["default"] = getUserReturn{
						// as returned in https://github.com/michaelklishin/rabbit-hole/blob/1de83b96b8ba1e29afd003143a9d8a8234d4e913/client.go#L153
						err: errUnauthorized}
				})
				It("does not PUT /api/users/default", func() {
					Eventually(fakeAdminClient.PutUserCallCount).Should(BeZero())
				})
			})
			Context("after GET /api/users/default", func() {
				BeforeEach(func() {
					fakeAuthClient.getUserReturn["default"] = getUserReturn{
						userInfo: &rabbithole.UserInfo{
							HashingAlgorithm: "myalgo",
							Tags:             rabbithole.UserTags{"mytag"},
						}}
				})
				It("does not PUT /api/users/default", func() {
					Eventually(fakeAdminClient.PutUserCallCount).Should(BeZero())
				})
			})

		})
		When("neither old nor new passwords are valid", func() {
			BeforeEach(func() {
				// Simulate failed authentication with both old and new passwords
				fakeAuthClient.getUserReturn["default"] = getUserReturn{err: errUnauthorized}
				fakeAuthClient.whoamiReturn = whoamiReturn{err: errUnauthorized}
			})

			It("updates the default user password in RabbitMQ", func() {
				Eventually(func() int {
					return len(fakeAdminClient.PutUserCalls)
				}).Should(Equal(1))

				expectedUserSettings := rabbithole.UserSettings{
					Name:             "default",
					Tags:             rabbithole.UserTags{"mytag"},
					Password:         "pwd2",
					HashingAlgorithm: "myalgo",
				}
				Expect(fakeAdminClient.PutUserCalls[0].Settings).To(Equal(expectedUserSettings))
			})
		})
	})

	When("admin user password updates", func() {
		JustBeforeEach(func() {
			write(adminPasswordFile, "newadminpwd")
		})
		When("admin user password in RabbitMQ is not yet up-to-date", func() {
			BeforeEach(func() {
				// Simulate that authentication fails so that an update is needed.
				fakeAuthClient.whoamiReturn = whoamiReturn{err: errUnauthorized}
				fakeAdminClient.getUserReturn["admin"] = getUserReturn{
					userInfo: &rabbithole.UserInfo{
						HashingAlgorithm: "adminalgo",
						Tags:             rabbithole.UserTags{"administrator"},
					},
				}
				fakeAdminClient.putUserReturn = putUserReturn{
					resp: &http.Response{
						Status: "204 No Content",
					},
				}
			})
			It("updates password in RabbitMQ for admin", func() {
				Eventually(func() int {
					return len(fakeAdminClient.PutUserCalls)
				}).Should(Equal(1))

				expectedSettings := rabbithole.UserSettings{
					Name:             "admin",
					Tags:             rabbithole.UserTags{"administrator"},
					Password:         "newadminpwd",
					HashingAlgorithm: "adminalgo",
				}
				Expect(fakeAdminClient.PutUserCalls[0].Settings).To(Equal(expectedSettings))
			})
			It("updates the admin password in the admin credentials file", func() {
				Eventually(func() string {
					cfg, err := ini.Load(u.AdminFile)
					Expect(err).NotTo(HaveOccurred())
					return cfg.Section(adminFileSection).Key(adminFilePasswordKey).String()
				}).Should(Equal("newadminpwd"))
			})
		})
		When("admin user password in RabbitMQ is up-to-date", func() {
			BeforeEach(func() {
				// Simulate that authentication now succeeds.
				fakeAuthClient.whoamiReturn = whoamiReturn{err: nil}
				fakeAdminClient.getUserReturn["admin"] = getUserReturn{
					userInfo: &rabbithole.UserInfo{
						HashingAlgorithm: "adminalgo",
						Tags:             rabbithole.UserTags{"administrator"},
					},
				}
			})
			It("does not update the admin password in RabbitMQ", func() {
				Eventually(fakeAdminClient.PutUserCallCount).Should(BeZero())
			})
			It("does not modify the admin credentials file", func() {
				Eventually(func() string {
					cfg, err := ini.Load(u.AdminFile)
					Expect(err).NotTo(HaveOccurred())
					return cfg.Section(adminFileSection).Key(adminFilePasswordKey).String()
				}).Should(Equal("newadminpwd"))
			})
		})
		When("neither old nor new passwords are valid", func() {
			BeforeEach(func() {
				// Simulate failed authentication with both old and new passwords for admin.
				fakeAdminClient.getUserReturn["admin"] = getUserReturn{err: errUnauthorized}
				fakeAdminClient.whoamiReturn = whoamiReturn{err: errUnauthorized}
				fakeAuthClient.whoamiReturn = whoamiReturn{err: errUnauthorized}
			})
			It("does not update the admin password in RabbitMQ", func() {
				Consistently(func() int {
					return len(fakeAdminClient.PutUserCalls)
				}).Should(BeZero())
			})
			It("does not update admin credentials file", func() {
				Eventually(func() string {
					cfg, err := ini.Load(u.AdminFile)
					Expect(err).NotTo(HaveOccurred())
					return cfg.Section(adminFileSection).Key(adminFilePasswordKey).String()
				}).Should(Equal("pwd1"))
			})
		})
	})
})

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

// initConfigFiles creates a fresh set of secret files for testing.
func initConfigFiles() {
	path := testWatchDir
	// Admin secrets.
	err := os.WriteFile(filepath.Join(path, adminUsernameFile), []byte("admin"), 0644)
	Expect(err).ToNot(HaveOccurred())
	err = os.WriteFile(filepath.Join(path, adminPasswordFile), []byte("pwd1"), 0644)
	Expect(err).ToNot(HaveOccurred())
	err = os.WriteFile(filepath.Join(path, adminTagFile), []byte("administrator"), 0644)
	Expect(err).ToNot(HaveOccurred())
	// Default secrets.
	err = os.WriteFile(filepath.Join(path, defaultUsernameFile), []byte("default"), 0644)
	Expect(err).ToNot(HaveOccurred())
	err = os.WriteFile(filepath.Join(path, defaultPasswordFile), []byte("pwd1"), 0644)
	Expect(err).ToNot(HaveOccurred())
	err = os.WriteFile(filepath.Join(path, defaultTagFile), []byte("mytag"), 0644)
	Expect(err).ToNot(HaveOccurred())

	cfg := ini.Empty()
	section, err := cfg.NewSection(adminFileSection)
	Expect(err).ToNot(HaveOccurred())
	_, err = section.NewKey(adminFileUserKey, "admin")
	Expect(err).ToNot(HaveOccurred())
	_, err = section.NewKey(adminFilePasswordKey, "pwd1")
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg.SaveTo(testAdminFile)).To(Succeed())
}

func write(filename, value string) {
	path := filepath.Join(testWatchDir, filename)
	err := os.WriteFile(path, []byte(value), 0644)
	Expect(err).ToNot(HaveOccurred())
	// Update file modification time to trigger a fsnotify event.
	err = os.Chtimes(path, time.Now(), time.Now())
	Expect(err).ToNot(HaveOccurred())
}

type fakeRabbitClient struct {
	Username string
	Password string

	// Track all calls with details
	GetUserCalls             []GetUserCall
	PutUserCalls             []PutUserCall
	WhoamiCalls              []WhoamiCall
	UpdatePermissionsInCalls []UpdatePermissionsInCall

	// Return values
	getUserReturn             map[string]getUserReturn
	putUserReturn             putUserReturn
	whoamiReturn              whoamiReturn
	updatePermissionsInReturn updatePermissionsInReturn
}

type GetUserCall struct {
	Username string
}

type PutUserCall struct {
	Username string
	Settings rabbithole.UserSettings
}

type UpdatePermissionsInCall struct {
	Vhost       string
	Username    string
	Permissions rabbithole.Permissions
}

type WhoamiCall struct{}

type getUserReturn struct {
	userInfo *rabbithole.UserInfo
	err      error
}

type putUserReturn struct {
	resp *http.Response
	err  error
}
type whoamiReturn struct {
	info *rabbithole.WhoamiInfo
	err  error
}

type updatePermissionsInReturn struct {
	resp *http.Response
	err  error
}

func (frc *fakeRabbitClient) GetUser(username string) (*rabbithole.UserInfo, error) {
	frc.GetUserCalls = append(frc.GetUserCalls, GetUserCall{Username: username})

	if ret, exists := frc.getUserReturn[username]; exists {
		return ret.userInfo, ret.err
	}
	return nil, fmt.Errorf("no user info configured for user %s", username)
}

func (frc *fakeRabbitClient) PutUser(username string, info rabbithole.UserSettings) (*http.Response, error) {
	frc.PutUserCalls = append(frc.PutUserCalls, PutUserCall{
		Username: username,
		Settings: info,
	})
	return frc.putUserReturn.resp, frc.putUserReturn.err
}

func (frc *fakeRabbitClient) UpdatePermissionsIn(vhost string, username string, permissions rabbithole.Permissions) (*http.Response, error) {
	frc.UpdatePermissionsInCalls = append(frc.UpdatePermissionsInCalls, UpdatePermissionsInCall{
		Vhost:       vhost,
		Username:    username,
		Permissions: permissions,
	})
	return frc.updatePermissionsInReturn.resp, frc.updatePermissionsInReturn.err
}

// Add back the missing interface methods
func (frc *fakeRabbitClient) GetUsername() string {
	return frc.Username
}

func (frc *fakeRabbitClient) SetUsername(username string) {
	frc.Username = username
}

func (frc *fakeRabbitClient) SetPassword(password string) {
	frc.Password = password
}

func (frc *fakeRabbitClient) Whoami() (*rabbithole.WhoamiInfo, error) {
	frc.WhoamiCalls = append(frc.WhoamiCalls, WhoamiCall{})
	return frc.whoamiReturn.info, frc.whoamiReturn.err
}

// Helper methods for counts
func (frc *fakeRabbitClient) GetUserCallCount() int {
	return len(frc.GetUserCalls)
}

func (frc *fakeRabbitClient) PutUserCallCount() int {
	return len(frc.PutUserCalls)
}

func (frc *fakeRabbitClient) WhoamiCallCount() int {
	return len(frc.WhoamiCalls)
}

func (frc *fakeRabbitClient) Reset() {
	frc.GetUserCalls = nil
	frc.PutUserCalls = nil
	frc.WhoamiCalls = nil
	frc.UpdatePermissionsInCalls = nil
	frc.Username = ""
	frc.Password = ""
}

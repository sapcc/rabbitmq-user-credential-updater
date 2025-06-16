package updater_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestUpdater(t *testing.T) {
	RegisterFailHandler(Fail)

	initLogging().WithName("test-updater")

	RunSpecs(t, "Updater Suite")
}

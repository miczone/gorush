package notify

import (
	"log"
	"testing"

	"github.com/miczone/gorush/config"
	"github.com/miczone/gorush/status"
)

func TestMain(m *testing.M) {
	cfg, _ := config.LoadConf()
	if err := status.InitAppStatus(cfg); err != nil {
		log.Fatal(err)
	}

	m.Run()
}

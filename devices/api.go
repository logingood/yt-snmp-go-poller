package devices

import (
	"context"

	"github.com/logingood/yt-snmp-go-poller/models"
)

type Devices interface {
	ListDevices(ctx context.Context) ([]models.Device, error)
}

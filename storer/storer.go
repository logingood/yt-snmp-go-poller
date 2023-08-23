package storer

import (
	"github.com/logingood/yt-snmp-go-poller/models"
)

type Storer interface {
	Write([]*models.SnmpInterfaceMetrics)
}

package snmp

import (
	"github.com/logingood/yt-snmp-go-poller/models"
)

type DecorateFunc func(*models.SnmpInterfaceMetrics) error
type Decorator func(DecorateFunc) DecorateFunc

func Compose(d DecorateFunc, decorators ...Decorator) DecorateFunc {
	for _, decorator := range decorators {
		d = decorator(d)
	}

	return d
}

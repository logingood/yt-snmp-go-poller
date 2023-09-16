package snmp

import (
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/logingood/yt-snmp-go-poller/models"
	"go.uber.org/zap"
)

type Client struct {
	client *gosnmp.GoSNMP
	logger *zap.Logger
	device *models.Device
}

func New(device *models.Device, logger *zap.Logger) *Client {
	if device.Hostname == nil {
		logger.Error("bad address")
		return nil
	}
	if device.SnmpVer == nil {
		logger.Error("bad version")
		return nil
	}

	g := &gosnmp.GoSNMP{
		Port:                    161,
		Retries:                 3,
		Timeout:                 5 * time.Second,
		Transport:               "udp",
		Target:                  *device.Hostname,
		UseUnconnectedUDPSocket: true,
		MaxOids:                 30,
	}

	switch *device.SnmpVer {
	case "1":
		g.Version = gosnmp.Version1
	case "v2c":
		g.Version = gosnmp.Version2c
		if device.Community == nil {
			logger.Error("bad community for v2c, must have a community")
			return nil
		}
		g.Community = *device.Community
	case "v3":
		if device.AuthLevel == nil || device.AuthName == nil || device.AuthPass == nil || device.CryptoPass == nil {
			logger.Error("bad device", zap.Any("dev", device))
			return nil
		}
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 *device.AuthName,
			AuthenticationProtocol:   gosnmp.SHA,
			AuthenticationPassphrase: *device.AuthPass,
			PrivacyProtocol:          gosnmp.AES,
			PrivacyPassphrase:        *device.CryptoPass,
		}

		switch *device.AuthLevel {
		case "noAuthNoPriv":
			g.MsgFlags = gosnmp.NoAuthNoPriv
		case "authNoPriv":
			g.MsgFlags = gosnmp.AuthNoPriv
		case "authPriv":
			g.MsgFlags = gosnmp.AuthPriv
		default:
			panic("bad security")
		}
	default:
		logger.Error("bad prootcol")
		return nil
	}

	return &Client{
		client: g,
		logger: logger,
		device: device,
	}
}

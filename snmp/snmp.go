package snmp

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/k-sone/snmpgo"
	"github.com/logingood/yt-snmp-go-poller/models"
	"go.uber.org/zap"
)

const (
	ifTableOid   = "1.3.6.1.2.1.2.2.1.1"
	ifTableAlias = "1.3.6.1.2.1.2.2.1.2"
)

var (
	ErrInterfaceIndexNotInteger = errors.New("interface index can not be non integer")
	ErrExpectOctetString        = errors.New("this value must be octet string")
)

var StrNameToOidMap = map[string]string{
	"ifAlias":           "1.3.6.1.2.1.31.1.1.1.18",
	"ifIndex":           "1.3.6.1.2.1.2.2.1.1",
	"ifDescr":           "1.3.6.1.2.1.2.2.1.2",
	"ifType":            "1.3.6.1.2.1.2.2.1.3",
	"ifMtu":             "1.3.6.1.2.1.2.2.1.4",
	"ifSpeed":           "1.3.6.1.2.1.2.2.1.5",
	"ifPhysAddress":     "1.3.6.1.2.1.2.2.1.6",
	"ifAdminStatus":     "1.3.6.1.2.1.2.2.1.7",
	"ifOperStatus":      "1.3.6.1.2.1.2.2.1.8",
	"ifLastChange":      "1.3.6.1.2.1.2.2.1.9",
	"ifInOctets":        "1.3.6.1.2.1.2.2.1.10",
	"ifInUcastPkts":     "1.3.6.1.2.1.2.2.1.11",
	"ifInNUcastPkts":    "1.3.6.1.2.1.2.2.1.12",
	"ifInDiscards":      "1.3.6.1.2.1.2.2.1.13",
	"ifInErrors":        "1.3.6.1.2.1.2.2.1.14",
	"ifInUnknownProtos": "1.3.6.1.2.1.2.2.1.15",
	"ifOutOctets":       "1.3.6.1.2.1.2.2.1.16",
	"ifOutUcastPkts":    "1.3.6.1.2.1.2.2.1.17",
	"ifOutNUcastPkts":   "1.3.6.1.2.1.2.2.1.18",
	"ifOutDiscards":     "1.3.6.1.2.1.2.2.1.19",
	"ifOutErrors":       "1.3.6.1.2.1.2.2.1.20",
	"ifOutQLen":         "1.3.6.1.2.1.2.2.1.21",
}

type Client struct {
	client *snmpgo.SNMP
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

	args := &snmpgo.SNMPArguments{
		Network: *device.Transport,
		Address: fmt.Sprintf("%s:%d", *device.Hostname, device.Port),
		Timeout: 1 * time.Second,
		Retries: 3,
	}

	switch *device.SnmpVer {
	case "1":
		args.Version = snmpgo.V1
	case "v2c":
		args.Version = snmpgo.V2c
		if device.Community == nil {
			logger.Error("bad community for v2c, must have a community")
			return nil
		}
		args.Community = *device.Community
	case "v3":
		if device.AuthLevel == nil || device.AuthName == nil || device.AuthPass == nil || device.CryptoPass == nil {
			logger.Error("bad device", zap.Any("dev", device))
			return nil
		}
		args.Version = snmpgo.V3
		args.UserName = *device.AuthName
		args.AuthPassword = *device.AuthPass
		args.AuthProtocol = snmpgo.Sha
		args.PrivPassword = *device.CryptoPass
		args.PrivProtocol = snmpgo.Aes

		switch *device.AuthLevel {
		case "noAuthNoPriv":
			args.SecurityLevel = snmpgo.NoAuthNoPriv
		case "authNoPriv":
			args.SecurityLevel = snmpgo.AuthNoPriv
		case "authPriv":
			args.SecurityLevel = snmpgo.AuthPriv
		default:
			panic("bad security")
		}
	default:
		logger.Error("bad prootcol")
		return nil
	}

	s, err := snmpgo.NewSNMP(*args)
	if err != nil {
		logger.Error("bad snmp", zap.Error(err))
		return nil
	}
	return &Client{
		client: s,
		logger: logger,
		device: device,
	}
}

// GetInterfacesMap builds an interface map setting correct indexes. This
// closure should be called the last if you use composer/middleware style function.
// it'll set initial map parameters such us device hostname, sysname, etc.
func (c *Client) GetInterfacesMap(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		pdu, err := c.walkOid(StrNameToOidMap["ifIndex"])
		if err != nil {
			return err
		}

		if c.device != nil && c.device.Hostname != nil {
			metricsMap.Hostname = *c.device.Hostname
		}
		if c.device != nil && c.device.SysName != nil {
			metricsMap.SysName = *c.device.SysName
		}
		metricsMap.CountersMap = make(map[int]models.SnmpInterface)

		for _, val := range pdu.VarBinds() {
			if val.Variable.Type() != "Integer" {
				// sanity check
				return ErrInterfaceIndexNotInteger
			}

			ifIndex, err := strconv.Atoi(val.Variable.String())
			if err != nil {
				return err
			}
			metricsMap.CountersMap[ifIndex] = models.SnmpInterface{}
		}

		return decorator(metricsMap)
	}
}

// SetIfName sets interface names for the snmp interfaces map
func (c *Client) SetIfName(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		pdu, err := c.walkOid(StrNameToOidMap["ifDescr"])
		if err != nil {
			return err
		}
		if err := setStringFromPDU(pdu, metricsMap.SetIfName); err != nil {
			return err
		}
		return decorator(metricsMap)
	}
}

// SetMacAddress sets interface mac for the snmp interfaces map
func (c *Client) SetMacAddress(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		pdu, err := c.walkOid(StrNameToOidMap["ifPhysAddress"])
		if err != nil {
			return err
		}
		if err := setStringFromPDU(pdu, metricsMap.SetMacAddress); err != nil {
			return err
		}
		return decorator(metricsMap)
	}
}

// SetIfAlias sets interface aliases for the snmp interfaces map
func (c *Client) SetIfAlias(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		pdu, err := c.walkOid(StrNameToOidMap["ifAlias"])
		if err != nil {
			return err
		}
		if err := setStringFromPDU(pdu, metricsMap.SetIfAlias); err != nil {
			return err
		}
		return decorator(metricsMap)
	}
}

// SetIfAdminStatus
func (c *Client) SetIfAdminStatus(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		pdu, err := c.walkOid(StrNameToOidMap["ifAdminStatus"])
		if err != nil {
			return err
		}
		if err := setBoolFromPDU(pdu, metricsMap.SetAdminStatus); err != nil {
			return err
		}
		return decorator(metricsMap)
	}
}

// SetIfOperStatus
func (c *Client) SetIfOperStatus(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		pdu, err := c.walkOid(StrNameToOidMap["ifOperStatus"])
		if err != nil {
			return err
		}
		if err := setBoolFromPDU(pdu, metricsMap.SetOperStatus); err != nil {
			return err
		}
		return decorator(metricsMap)
	}
}

// SetSpeed
func (c *Client) SetSpeed(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		pdu, err := c.walkOid(StrNameToOidMap["ifSpeed"])
		if err != nil {
			return err
		}
		if err := setInt64FromPDU(pdu, metricsMap.SetSpeed); err != nil {
			return err
		}
		return decorator(metricsMap)
	}
}

// SetMtu
func (c *Client) SetMtu(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		pdu, err := c.walkOid(StrNameToOidMap["ifMtu"])
		if err != nil {
			return err
		}
		if err := setInt64FromPDU(pdu, metricsMap.SetMtu); err != nil {
			return err
		}
		return decorator(metricsMap)
	}
}

// SetCounters sets snmp counters for oids from 10 to 21
func (c *Client) SetCounters(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		pdu, err := c.walkOid(
			StrNameToOidMap["ifInOctets"],
			StrNameToOidMap["ifInUcastPkts"],
			StrNameToOidMap["ifInNUcastPkts"],
			StrNameToOidMap["ifInDiscards"],
			StrNameToOidMap["ifInErrors"],
			StrNameToOidMap["ifInUnknownProtos"],
			StrNameToOidMap["ifOutOctets"],
			StrNameToOidMap["ifOutUcastPkts"],
			StrNameToOidMap["ifOutNUcastPkts"],
			StrNameToOidMap["ifOutDiscards"],
			StrNameToOidMap["ifOutErrors"],
			StrNameToOidMap["ifOutQLen"],
		)
		if err != nil {
			return err
		}
		if err := setCountersFromPDU(pdu, metricsMap.SetCounters); err != nil {
			return err
		}
		return decorator(metricsMap)
	}
}

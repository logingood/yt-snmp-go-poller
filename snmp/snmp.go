package snmp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
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
	"ifAlias":       "1.3.6.1.2.1.31.1.1.1.18",
	"ifIndex":       "1.3.6.1.2.1.2.2.1.1",
	"ifDescr":       "1.3.6.1.2.1.2.2.1.2",
	"ifType":        "1.3.6.1.2.1.2.2.1.3",
	"ifMtu":         "1.3.6.1.2.1.2.2.1.4",
	"ifSpeed":       "1.3.6.1.2.1.2.2.1.5",
	"ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
	"ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
	"ifOperStatus":  "1.3.6.1.2.1.2.2.1.8",
	"ifLastChange":  "1.3.6.1.2.1.2.2.1.9",
	// HC counters
	"ifInMulticastPkts":          "1.3.6.1.2.1.31.1.1.1.2",
	"ifInBroadcastPkts":          "1.3.6.1.2.1.31.1.1.1.3",
	"ifOutMulticastPkts":         "1.3.6.1.2.1.31.1.1.1.4",
	"ifOutBroadcastPkts":         "1.3.6.1.2.1.31.1.1.1.5",
	"ifHCInOctets":               "1.3.6.1.2.1.31.1.1.1.6",
	"ifHCInUcastPkts":            "1.3.6.1.2.1.31.1.1.1.7",
	"ifHCInMulticastPkts":        "1.3.6.1.2.1.31.1.1.1.8",
	"ifHCInBroadcastPkts":        "1.3.6.1.2.1.31.1.1.1.9",
	"ifHCOutOctets":              "1.3.6.1.2.1.31.1.1.1.10",
	"ifHCOutUcastPkts":           "1.3.6.1.2.1.31.1.1.1.11",
	"ifHCOutMulticastPkts":       "1.3.6.1.2.1.31.1.1.1.12",
	"ifHCOutBroadcastPkts":       "1.3.6.1.2.1.31.1.1.1.13",
	"ifHighSpeed":                "1.3.6.1.2.1.31.1.1.1.15",
	"ifCounterDiscontinuityTime": "1.3.6.1.2.1.31.1.1.1.19",

	"ifInDiscards":  "1.3.6.1.2.1.2.2.1.13",
	"ifInErrors":    "1.3.6.1.2.1.2.2.1.14",
	"ifOutDiscards": "1.3.6.1.2.1.2.2.1.19",
	"ifOutErrors":   "1.3.6.1.2.1.2.2.1.20",
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
		Timeout: 6 * time.Second,
		Retries: 0,
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
		logger.Error("bad snmp", zap.Error(err), zap.Any("device", device.SysName))
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

// SetCounters sets snmp counters for oids from 10 to 21
func (c *Client) SetCounters(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		pdu, err := c.walkOid(
			StrNameToOidMap["ifDescr"],
			StrNameToOidMap["ifPhysAddress"],
			StrNameToOidMap["ifAlias"],
			StrNameToOidMap["ifAdminStatus"],
			StrNameToOidMap["ifOperStatus"],
			StrNameToOidMap["ifSpeed"],
			StrNameToOidMap["ifMtu"],

			StrNameToOidMap["ifInMulticastPkts"],
			StrNameToOidMap["ifInBroadcastPkts"],
			StrNameToOidMap["ifOutMulticastPkts"],
			StrNameToOidMap["ifOutBroadcastPkts"],
			StrNameToOidMap["ifHCInOctets"],
			StrNameToOidMap["ifHCInUcastPkts"],
			StrNameToOidMap["ifHCInMulticastPkts"],
			StrNameToOidMap["ifHCInBroadcastPkts"],
			StrNameToOidMap["ifHCOutOctets"],
			StrNameToOidMap["ifHCOutUcastPkts"],
			StrNameToOidMap["ifHCOutMulticastPkts"],
			StrNameToOidMap["ifHCOutBroadcastPkts"],
			StrNameToOidMap["ifHighSpeed"],
			StrNameToOidMap["ifCounterDiscontinuityTime"],

			StrNameToOidMap["ifInDiscards"],
			StrNameToOidMap["ifInErrors"],
			StrNameToOidMap["ifOutDiscards"],
			StrNameToOidMap["ifOutErrors"],
		)
		if err != nil {
			return err
		}

		for _, val := range pdu.VarBinds() {
			myoid := val.Oid.String()
			indexpos := strings.LastIndex(myoid, ".")
			index, _ := strconv.Atoi(myoid[indexpos+1:])
			intVal, err := val.Variable.BigInt()
			if err != nil {
				return err
			}
			partsMyOid := strings.Split(myoid, ".")
			origOID := strings.Join(partsMyOid[0:len(partsMyOid)-1], ".")

			name := reverseMap(StrNameToOidMap)[origOID]
			switch name {
			case "ifPhysAddress":
				metricsMap.SetMacAddress(intVal.String(), index)
			case "ifAlias":
				metricsMap.SetIfAlias(intVal.String(), index)
			case "ifAdminStatus":
				metricsMap.SetAdminStatus(intVal.Int64() == 1, index)
			case "ifOperStatus":
				metricsMap.SetOperStatus(intVal.Int64() == 1, index)
			case "ifSpeed":
				metricsMap.SetSpeed(intVal.Int64(), index)
			case "ifMtu":
				metricsMap.SetMtu(intVal.Int64(), index)
			default:
				metricsMap.SetCounters(intVal, index, name)
			}
		}
		// it is safe to close the client here
		c.client.Close()
		return decorator(metricsMap)
	}
}

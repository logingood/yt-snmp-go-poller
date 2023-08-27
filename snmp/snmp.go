package snmp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
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
	"ifAlias":       ".1.3.6.1.2.1.31.1.1.1.18",
	"ifIndex":       ".1.3.6.1.2.1.2.2.1.1",
	"ifDescr":       ".1.3.6.1.2.1.2.2.1.2",
	"ifType":        ".1.3.6.1.2.1.2.2.1.3",
	"ifMtu":         ".1.3.6.1.2.1.2.2.1.4",
	"ifSpeed":       ".1.3.6.1.2.1.2.2.1.5",
	"ifPhysAddress": ".1.3.6.1.2.1.2.2.1.6",
	"ifAdminStatus": ".1.3.6.1.2.1.2.2.1.7",
	"ifOperStatus":  ".1.3.6.1.2.1.2.2.1.8",
	"ifLastChange":  ".1.3.6.1.2.1.2.2.1.9",
	// HC counters
	"ifInMulticastPkts":          ".1.3.6.1.2.1.31.1.1.1.2",
	"ifInBroadcastPkts":          ".1.3.6.1.2.1.31.1.1.1.3",
	"ifOutMulticastPkts":         ".1.3.6.1.2.1.31.1.1.1.4",
	"ifOutBroadcastPkts":         ".1.3.6.1.2.1.31.1.1.1.5",
	"ifHCInOctets":               ".1.3.6.1.2.1.31.1.1.1.6",
	"ifHCInUcastPkts":            ".1.3.6.1.2.1.31.1.1.1.7",
	"ifHCInMulticastPkts":        ".1.3.6.1.2.1.31.1.1.1.8",
	"ifHCInBroadcastPkts":        ".1.3.6.1.2.1.31.1.1.1.9",
	"ifHCOutOctets":              ".1.3.6.1.2.1.31.1.1.1.10",
	"ifHCOutUcastPkts":           ".1.3.6.1.2.1.31.1.1.1.11",
	"ifHCOutMulticastPkts":       ".1.3.6.1.2.1.31.1.1.1.12",
	"ifHCOutBroadcastPkts":       ".1.3.6.1.2.1.31.1.1.1.13",
	"ifHighSpeed":                ".1.3.6.1.2.1.31.1.1.1.15",
	"ifCounterDiscontinuityTime": ".1.3.6.1.2.1.31.1.1.1.19",

	"ifInDiscards":  ".1.3.6.1.2.1.2.2.1.13",
	"ifInErrors":    ".1.3.6.1.2.1.2.2.1.14",
	"ifOutDiscards": ".1.3.6.1.2.1.2.2.1.19",
	"ifOutErrors":   ".1.3.6.1.2.1.2.2.1.20",

	// perhaps we want ports too
	"lldpRemSysName": ".1.0.8802.1.1.2.1.4.1.1.9",
}

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

// GetInterfacesMap builds an interface map setting correct indexes. This
// closure should be called the last if you use composer/middleware style function.
// it'll set initial map parameters such us device hostname, sysname, etc.
func (c *Client) GetInterfacesMap(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		err := c.client.Connect()
		if err != nil {
			c.logger.Error("failed to connect", zap.Error(err))
			return err
		}

		pdu, err := c.walkOid(StrNameToOidMap["ifIndex"])
		if err != nil {
			c.logger.Error("error walk", zap.Error(err))
			return err
		}

		if c.device != nil && c.device.Hostname != nil {
			metricsMap.Hostname = *c.device.Hostname
		}
		if c.device != nil && c.device.SysName != nil {
			metricsMap.SysName = *c.device.SysName
		}
		if c.device != nil && c.device.Hardware != nil {
			metricsMap.Hardware = *c.device.Hardware
		}
		if c.device != nil && c.device.OS != nil {
			metricsMap.OS = *c.device.OS
		}
		if c.device != nil && c.device.Serial != nil {
			metricsMap.Serial = *c.device.Serial
		}
		if c.device != nil && c.device.UptimeSeconds != nil {
			metricsMap.Uptime = *c.device.UptimeSeconds
		}
		if c.device != nil && c.device.Location != nil {
			metricsMap.Location = *c.device.Location
		}
		if c.device != nil && c.device.SysDescr != nil {
			metricsMap.SysDescr = *c.device.SysDescr
		}
		if c.device != nil && c.device.Lat != nil && c.device.Lng != nil {
			metricsMap.Lat = *c.device.Lat
			metricsMap.Lng = *c.device.Lng
		}

		metricsMap.CountersMap = make(map[int]models.SnmpInterface)

		for _, val := range pdu {
			if val.Type != gosnmp.Integer {
				// sanity check
				c.logger.Error("not integer walk")
				return ErrInterfaceIndexNotInteger
			}

			ifIndex, ok := val.Value.(int)
			if !ok {
				return ErrInterfaceIndexNotInteger
			}
			metricsMap.CountersMap[ifIndex] = models.SnmpInterface{}
		}

		return decorator(metricsMap)
	}
}

// SetCounters sets snmp counters for oids from 10 to 21
func (c *Client) SetCounters(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		defer func() {
			c.logger.Info("close the conn")
			c.client.Conn.Close()
		}()
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

			StrNameToOidMap["lldpRemSysName"],
		)
		if err != nil {
			c.logger.Error("counters bad error", zap.Error(err), zap.Any("device", c.device.SysName))
			return err
		}
		metricsMap.Time = time.Now().UTC().Unix()

		for _, val := range pdu {
			myoid := val.Name
			indexpos := strings.LastIndex(myoid, ".")
			index, _ := strconv.Atoi(myoid[indexpos+1:])
			partsMyOid := strings.Split(myoid, ".")
			origOID := strings.Join(partsMyOid[0:len(partsMyOid)-1], ".")
			if strings.Contains(origOID, StrNameToOidMap["lldpRemSysName"]) {
				origOID = StrNameToOidMap["lldpRemSysName"]
			}
			name := reverseMap(StrNameToOidMap)[origOID]
			switch name {
			case "ifPhysAddress":
				v := ""
				switch val.Type {
				case gosnmp.OctetString:
					bytes := val.Value.([]byte)
					split := ""
					for _, b := range bytes {
						if v != "" {
							split = ":"
						}
						v += fmt.Sprintf(split+"%x", b)
					}
				default:
					v = fmt.Sprint(val.Value)
				}
				metricsMap.SetMacAddress(v, index)
			case "ifAlias":
				metricsMap.SetIfAlias(string(val.Value.([]byte)), index)
			case "ifDescr":
				metricsMap.SetIfName(string(val.Value.([]byte)), index)
			case "ifAdminStatus":
				intVal := gosnmp.ToBigInt(val.Value)
				metricsMap.SetAdminStatus(intVal.Int64() == 1, index)
			case "ifOperStatus":
				intVal := gosnmp.ToBigInt(val.Value)
				metricsMap.SetOperStatus(intVal.Int64() == 1, index)
			case "ifSpeed":
				intVal := gosnmp.ToBigInt(val.Value)
				metricsMap.SetSpeed(intVal.Int64(), index)
			case "ifMtu":
				intVal := gosnmp.ToBigInt(val.Value)
				metricsMap.SetMtu(intVal.Int64(), index)
			case "lldpRemSysName":
				metricsMap.SetNeighbour(string(val.Value.([]byte)), index)
			default:
				intVal := gosnmp.ToBigInt(val.Value)
				metricsMap.SetCounters(intVal, index, name)
			}
		}

		return decorator(metricsMap)
	}
}

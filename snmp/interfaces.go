package snmp

import (
	"errors"
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

	/*
		"storageDescr": ".1.3.6.1.2.1.25.2.3.1.3 ",
		"inBytes":      ".1.3.6.1.2.1.25.2.3.1.4",
		"usage":        ".1.3.6.1.2.1.25.2.3.1.6",

		"cpu":    "1.3.6.1.2.1.25.3.3.1.2",
		"memory": "1.3.6.1.2.1.25.2.2",
	*/
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

		setDeviceDataForInterfaces(metricsMap, c.device)

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

		c.logger.Debug("got interface indexes", zap.Any("indexes", len(metricsMap.CountersMap)))

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
		oids := []string{}
		for k, v := range StrNameToOidMap {
			if k == "ifDescr" {
				continue
			}
			oids = append(oids, v)
		}

		pdu, err := c.walkOid(StrNameToOidMap["ifDescr"], oids...)
		if err != nil {
			c.logger.Error("counters bad error", zap.Error(err), zap.Any("device", c.device.SysName))
			return err
		}
		metricsMap.Time = time.Now().UTC().Unix()

		setPduMetricsMap(metricsMap, pdu)
		c.logger.Debug("set pdu metrics", zap.Any("metrics_count", len(metricsMap.CountersMap)))
		return decorator(metricsMap)
	}
}

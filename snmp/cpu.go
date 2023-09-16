package snmp

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/logingood/yt-snmp-go-poller/models"
	"go.uber.org/zap"
)

var CpuOidMap = map[string]string{
	"cpu": "1.3.6.1.2.1.25.3.3.1.2",
}

// GetInterfacesMap builds an interface map setting correct indexes. This
// closure should be called the last if you use composer/middleware style function.
// it'll set initial map parameters such us device hostname, sysname, etc.
func (c *Client) GetCpuMap(decorator DecorateFunc) DecorateFunc {
	return func(metricsMap *models.SnmpInterfaceMetrics) error {
		err := c.client.Connect()
		if err != nil {
			c.logger.Error("failed to connect", zap.Error(err))
			return err
		}

		pdu, err := c.walkOid(CpuOidMap["cpu"])
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

// SetCpuCounters sets cpu snmp counters
func (c *Client) SetCpuCounters(decorator DecorateFunc) DecorateFunc {
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

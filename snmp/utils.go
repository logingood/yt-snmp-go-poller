package snmp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
	"github.com/logingood/yt-snmp-go-poller/models"
)

func setDeviceDataForInterfaces(metricsMap *models.SnmpInterfaceMetrics, device *models.Device) {
	if device != nil && device.Hostname != nil {
		metricsMap.Hostname = *device.Hostname
	}
	if device != nil && device.SysName != nil {
		metricsMap.SysName = *device.SysName
	}
	if device != nil && device.Hardware != nil {
		metricsMap.Hardware = *device.Hardware
	}
	if device != nil && device.OS != nil {
		metricsMap.OS = *device.OS
	}
	if device != nil && device.Serial != nil {
		metricsMap.Serial = *device.Serial
	}
	if device != nil && device.UptimeSeconds != nil {
		metricsMap.Uptime = *device.UptimeSeconds
	}
	if device != nil && device.Location != nil {
		metricsMap.Location = *device.Location
	}
	if device != nil && device.SysDescr != nil {
		metricsMap.SysDescr = *device.SysDescr
	}
	if device != nil && device.Lat != nil && device.Lng != nil {
		metricsMap.Lat = *device.Lat
		metricsMap.Lng = *device.Lng
	}
}

func setPduMetricsMap(metricsMap *models.SnmpInterfaceMetrics, pdu []gosnmp.SnmpPDU) {
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
}

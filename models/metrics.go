package models

import (
	"math/big"
	"time"
)

// SnmpInterface index is 1.3.6.1.2.1.2.2.1.1. We use index as a key of the
// map SnmpInterfaceMetrics.
type SnmpInterface struct {
	IfAlias     string        `ch:"if_alias" json:"if_alias"`         // 1.3.6.1.2.1.31.1.1.1.18
	IfName      string        `ch:"if_name" json:"if_name"`           // 1.3.6.1.2.1.2.2.1.2
	IfType      int32         `ch:"if_type" json:"if_type"`           // 1.3.6.1.2.1.2.2.1.3
	Mtu         int64         `ch:"mtu" json:"mtu"`                   // 1.3.6.1.2.1.2.2.1.4
	Speed       int64         `ch:"speed" json:"speed"`               // 1.3.6.1.2.1.2.2.1.5
	MacAddress  string        `ch:"mac_address" json:"mac_address"`   // 1.3.6.1.2.1.2.2.1.6
	AdminStatus bool          `ch:"admin_status" json:"admin_status"` // 1.3.6.1.2.1.2.2.1.7
	OperStatus  bool          `ch:"oper_status" json:"oper_status"`   // 1.3.6.1.2.1.2.2.1.8
	LastChange  time.Duration `ch:"last_change" json:"last_change"`   // .9

	// Counters will be from .10 to .21
	Counters map[string]*big.Int `ch:"-" json:"counters"`
}

type SnmpInterfaceMetrics struct {
	CountersMap map[int]SnmpInterface
	SysName     string
	Hostname    string
}

func (s *SnmpInterfaceMetrics) SetIfName(val string, index int) {
	updateValue := s.CountersMap[index]
	updateValue.IfName = val
	s.CountersMap[index] = updateValue
}

func (s *SnmpInterfaceMetrics) SetIfAlias(val string, index int) {
	updateValue := s.CountersMap[index]
	updateValue.IfAlias = val
	s.CountersMap[index] = updateValue
}

func (s *SnmpInterfaceMetrics) SetMacAddress(val string, index int) {
	updateValue := s.CountersMap[index]
	updateValue.MacAddress = val
	s.CountersMap[index] = updateValue
}

func (s *SnmpInterfaceMetrics) SetAdminStatus(val bool, index int) {
	updateValue := s.CountersMap[index]
	updateValue.AdminStatus = val
	s.CountersMap[index] = updateValue
}

func (s *SnmpInterfaceMetrics) SetOperStatus(val bool, index int) {
	updateValue := s.CountersMap[index]
	updateValue.OperStatus = val
	s.CountersMap[index] = updateValue
}

func (s *SnmpInterfaceMetrics) SetMtu(val int64, index int) {
	updateValue := s.CountersMap[index]
	updateValue.Mtu = val
	s.CountersMap[index] = updateValue
}

func (s *SnmpInterfaceMetrics) SetSpeed(val int64, index int) {
	updateValue := s.CountersMap[index]
	updateValue.Speed = val
	s.CountersMap[index] = updateValue
}

func (s *SnmpInterfaceMetrics) SetCounters(val *big.Int, index int, coutner string) {
	updateValue := s.CountersMap[index]
	if updateValue.Counters == nil {
		updateValue.Counters = map[string]*big.Int{}
	}
	updateValue.Counters[coutner] = val
	s.CountersMap[index] = updateValue
}

package snmp

import (
	"math/big"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

// setStringFromPDU takes a pdu result as an input, checks for an expectedType
// and and calls the setFunc
func setStringFromPDU(
	pdu *gosnmp.SnmpPacket,
	setFunc func(string, int),
) error {
	for _, val := range pdu.Variables {
		myoid := val.Name
		indexpos := strings.LastIndex(myoid, ".")
		index, _ := strconv.Atoi(myoid[indexpos+1:])
		setFunc(string(val.Value.([]byte)), index)

	}

	return nil
}

// setBoolFromPDU takes a pdu result as an input, checks for an expectedType
// and and calls the setFunc
func setBoolFromPDU(
	pdu *gosnmp.SnmpPacket,
	setFunc func(bool, int),
) error {
	for _, val := range pdu.Variables {
		myoid := val.Name
		indexpos := strings.LastIndex(myoid, ".")
		index, _ := strconv.Atoi(myoid[indexpos+1:])
		setFunc(string(val.Value.([]byte)) == "1", index)
	}

	return nil
}

// setCountersFromPDU
func setCountersFromPDU(
	pdu *gosnmp.SnmpPacket,
	setFunc func(*big.Int, int, string),
) error {
	for _, val := range pdu.Variables {
		myoid := val.Name
		indexpos := strings.LastIndex(myoid, ".")
		index, _ := strconv.Atoi(myoid[indexpos+1:])
		partsMyOid := strings.Split(myoid, ".")
		origOID := strings.Join(partsMyOid[0:len(partsMyOid)-1], ".")
		intVal := gosnmp.ToBigInt(val.Value)
		setFunc(intVal, index, reverseMap(StrNameToOidMap)[origOID])
	}

	return nil
}

// walkOid walks the given oid for an snmp device
func (c *Client) walkOid(oid string, otherOids ...string) ([]gosnmp.SnmpPDU, error) {
	inputOids := []string{oid}
	inputOids = append(inputOids, otherOids...)

	pdus := []gosnmp.SnmpPDU{}
	for _, oid := range inputOids {
		pdu, err := c.client.WalkAll(oid)
		if err != nil {
			c.logger.Error("bad response", zap.Error(err), zap.Any("device", *c.device.SysName), zap.Any("oid", oid), zap.Any("other oids", otherOids))
			return nil, err
		}
		pdus = append(pdus, pdu...)
	}

	return pdus, nil
}

func reverseMap(m map[string]string) map[string]string {
	n := make(map[string]string, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
}

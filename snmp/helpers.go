package snmp

import (
	"math/big"
	"strconv"
	"strings"

	"github.com/k-sone/snmpgo"
	"go.uber.org/zap"
)

// setStringFromPDU takes a pdu result as an input, checks for an expectedType
// and and calls the setFunc
func setStringFromPDU(
	pdu snmpgo.Pdu,
	setFunc func(string, int),
) error {
	for _, val := range pdu.VarBinds() {
		myoid := val.Oid.String()
		indexpos := strings.LastIndex(myoid, ".")
		index, _ := strconv.Atoi(myoid[indexpos+1:])
		if val.Variable.Type() != "OctetString" {
			// sanity check
			return ErrExpectOctetString
		}

		setFunc(val.Variable.String(), index)
	}

	return nil
}

// setBoolFromPDU takes a pdu result as an input, checks for an expectedType
// and and calls the setFunc
func setBoolFromPDU(
	pdu snmpgo.Pdu,
	setFunc func(bool, int),
) error {
	for _, val := range pdu.VarBinds() {
		myoid := val.Oid.String()
		indexpos := strings.LastIndex(myoid, ".")
		index, _ := strconv.Atoi(myoid[indexpos+1:])
		setFunc(val.Variable.String() == "1", index)
	}

	return nil
}

// setInt64FromPDU takes a pdu result as an input, checks for an expectedType
// and and calls the setFunc
func setInt64FromPDU(
	pdu snmpgo.Pdu,
	setFunc func(int64, int),
) error {
	for _, val := range pdu.VarBinds() {
		myoid := val.Oid.String()
		indexpos := strings.LastIndex(myoid, ".")
		index, _ := strconv.Atoi(myoid[indexpos+1:])

		intVal, err := val.Variable.BigInt()
		if err != nil {
			return err
		}
		setFunc(intVal.Int64(), index)
	}

	return nil
}

// setIntFromPDU takes a pdu result as an input, checks for an expectedType
// and and calls the setFunc
func setIntFromPDU(
	pdu snmpgo.Pdu,
	setFunc func(int, int),
) error {
	for _, val := range pdu.VarBinds() {
		myoid := val.Oid.String()
		indexpos := strings.LastIndex(myoid, ".")
		index, _ := strconv.Atoi(myoid[indexpos+1:])

		intVal, err := val.Variable.BigInt()
		if err != nil {
			return err
		}
		setFunc(int(intVal.Int64()), index)
	}

	return nil
}

// setCountersFromPDU
func setCountersFromPDU(
	pdu snmpgo.Pdu,
	setFunc func(*big.Int, int, string),
) error {
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

		setFunc(intVal, index, reverseMap(StrNameToOidMap)[origOID])
	}

	return nil
}

// walkOid walks the given oid for an snmp device
func (c *Client) walkOid(oid string, otherOids ...string) (snmpgo.Pdu, error) {
	inputOids := []string{oid}
	inputOids = append(inputOids, otherOids...)
	oids, err := snmpgo.NewOids(
		inputOids,
	)
	if err != nil {
		return nil, err
	}

	pdu, err := c.client.GetBulkWalk(oids, 0, 3)
	if err != nil {
		c.logger.Error("bad response", zap.Error(err))
		return nil, err
	}

	if pdu.ErrorStatus() != snmpgo.NoError {
		c.logger.Error("walk error", zap.Any("error", pdu.ErrorStatus()))
		return nil, err
	}

	return pdu, nil
}

func reverseMap(m map[string]string) map[string]string {
	n := make(map[string]string, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
}

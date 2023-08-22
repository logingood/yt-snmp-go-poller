package models

type Device struct {
	DeviceID    int32   `db:"device_id" json:"device_id"`
	Hostname    *string `db:"hostname" json:"hostname"`
	SysName     *string `db:"sysName" json:"sysname"`
	Community   *string `db:"community" json:"community"`
	AuthLevel   *string `db:"authlevel" json:"authlevel"`
	AuthName    *string `db:"authname"`
	AuthPass    *string `db:"authpass" json:"authpass"`
	AuthAlgo    *string `db:"authalgo" json:"authalgo"`
	CryptoPass  *string `db:"cryptopass" json:"cryptopass"`
	CryptoAlgo  *string `db:"cryptoalgo" json:"cryptoalgo"`
	SnmpVer     *string `db:"snmpver" json:"snmpver"`
	Port        int     `db:"port" json:"port"`
	Transport   *string `db:"transport" json:"transport"`
	BgpLocalAs  []uint8 `db:"bgpLocalAs" json:"bgplocalas"`
	SysObjectID *string `db:"sysObjectID" json:"sysobjectid"`
	SysDescr    *string `db:"sysDescr" json:"sysdescr"`
	SysContact  *string `db:"sysContact" json:"syscontact"`
	Version     *string `db:"version" json:"version"`
	Hardware    *string `db:"hardware" json:"hardware"`
	Features    *string `db:"features" json:"features"`
	OS          *string `db:"os" json:"os"`
	Status      bool    `db:"status" json:"status"`
}

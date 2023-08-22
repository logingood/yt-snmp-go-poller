## Yet another librenms go poller

Inspired by https://github.com/geordish/librenms-go-poller, however we decided
to implement queueing within the poller, to avoid additional dependencies.

Destination for the metrics is going to be Clickhouse, however any other
transport can be easily plugged in via corresponding storer.

The idea is to get the devices via sql from LibreNMS database, poll them for
interface statistics and any other SNMP metrics that we need.
Flattened metrics will be sent to Clickhouse in bulk uploads.

### Config

Query will require the exact fields, otherwise the model won't unmarshal.

```
export DB_USERNAME=librenms
export DB_PASSWORD=foo
export DB_HOST=localhost
export DB_PORT=3306
export DB_NAME=librenms
export QUERY="SELECT device_id, hostname, sysName, community, authlevel, authname, authpass, authalgo, cryptopass, cryptoalgo, snmpver, port, transport,  bgpLocalAs, sysObjectID, sysDescr, sysContact, version, hardware, features, os, status from devices"
```


### Running

The code is WIP/POC, so run at your own risk
`cd cmd/poller`
`go run .`

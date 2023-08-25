package chouse

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/logingood/yt-snmp-go-poller/models"
	"github.com/logingood/yt-snmp-go-poller/snmp"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type ClickhouseClient struct {
	dbName         string
	tableName      string
	flushBatchSize int
	conn           driver.Conn
	queue          chan *models.SnmpInterfaceMetrics
	logger         *zap.Logger
}

func New(logger *zap.Logger, conn driver.Conn, queueSize int, dbName, tableName string, flushBatchSize int,
) *ClickhouseClient {
	return &ClickhouseClient{
		logger:         logger,
		conn:           conn,
		queue:          make(chan *models.SnmpInterfaceMetrics, queueSize),
		dbName:         dbName,
		tableName:      tableName,
		flushBatchSize: flushBatchSize,
	}
}

func (c *ClickhouseClient) Write(metric *models.SnmpInterfaceMetrics) {
	c.logger.Info("enqueue metric", zap.Any("hostname", metric.Hostname))
	c.enqueue(metric)
	return
}

func (c *ClickhouseClient) enqueue(flow *models.SnmpInterfaceMetrics) {
	c.queue <- flow
}

func (c *ClickhouseClient) StartQueue(ctx context.Context, errGroup *errgroup.Group) {
	errGroup.Go(func() error {
		metrics := []*models.SnmpInterfaceMetrics{}
		for j := range c.queue {

			c.logger.Info("appending metric", zap.Any("hostname", j.Hostname))
			metrics = append(metrics, j)
			if len(metrics) == c.flushBatchSize {
				c.logger.Info("insert time", zap.Any("metrics number", len(metrics)))
				if err := c.insert(metrics); err != nil {
					c.logger.Error("error", zap.Error(err))
					//return err
				}
				metrics = nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// keep working
			}
		}
		return nil
	})
}

func (c *ClickhouseClient) insert(metrics []*models.SnmpInterfaceMetrics) error {
	batch, err := c.conn.PrepareBatch(context.Background(), fmt.Sprintf("INSERT INTO %s.%s", c.dbName, c.tableName))
	if err != nil {
		return err
	}

	for _, metric := range metrics {
		// TODO convert IP to []byte

		for _, counters := range metric.CountersMap {

			for k := range snmp.StrNameToOidMap {
				if counters.Counters == nil {
					counters.Counters = map[string]*big.Int{}
				}
				if counters.Counters[k] == nil {
					bigInt := big.NewInt(0)
					counters.Counters[k] = bigInt
				}
			}
			batch.Append(
				time.Now().UTC().Unix(),
				metric.SysName,
				metric.Hostname,
				counters.IfAlias,
				counters.IfName,
				counters.IfType,
				counters.Mtu,
				counters.Speed,
				counters.MacAddress,
				counters.AdminStatus,
				counters.OperStatus,

				counters.Counters["ifInMulticastPkts"].Int64(),
				counters.Counters["ifInBroadcastPkts"].Int64(),
				counters.Counters["ifOutMulticastPkts"].Int64(),
				counters.Counters["ifOutBroadcastPkts"].Int64(),
				counters.Counters["ifHCInOctets"].Int64(),
				counters.Counters["ifHCInUcastPkts"].Int64(),
				counters.Counters["ifHCInMulticastPkts"].Int64(),
				counters.Counters["ifHCInBroadcastPkts"].Int64(),
				counters.Counters["ifHCOutOctets"].Int64(),
				counters.Counters["ifHCOutUcastPkts"].Int64(),
				counters.Counters["ifHCOutMulticastPkts"].Int64(),
				counters.Counters["ifHCOutBroadcastPkts"].Int64(),
				counters.Counters["ifHighSpeed"].Int64(),
				counters.Counters["ifCounterDiscontinuityTime"].Int64(),
				counters.Counters["ifInDiscards"].Int64(),
				counters.Counters["ifInErrors"].Int64(),
				counters.Counters["ifOutDiscards"].Int64(),
				counters.Counters["ifOutErrors"].Int64(),
			)

		}
	}
	if err := batch.Send(); err != nil {
		return err
	}
	c.logger.Info("sent successfully", zap.Int("metrics", len(metrics)))
	return nil
}

func (c *ClickhouseClient) InitDb(ctx context.Context) error {
	stm := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s.%s (
		time Int64,
		sys_name VARCHAR(255),
		hostname IPv6,
		if_alias VARCHAR(255),
		if_name VARCHAR(255),
		if_type Int32,
		mtu Int64,
		speed Int64,
		mac_address VARCHAR(255),
		admin_status Bool,
		oper_status Bool,
		if_in_multicast_pkts Int64,
		if_in_broadcast_pkts Int64,
		if_out_multicast_pkts Int64,
		if_out_broadcast_pkts Int64,
		if_hcin_octets Int64,
		if_hcin_ucast_pkts Int64,
		if_hcin_multicast_pkts Int64,
		if_hcin_broadcast_pkts Int64,
		if_hcout_octets Int64,
		if_hcout_ucast_pkts  Int64,
		if_hcout_multicast_pkts  Int64,
		if_hcout_broadcast_pkts  Int64,
		if_high_speed Int64,
		if_counter_discontinuity_time Int64,
		if_in_discards Int64,
		if_in_errors Int64,
		if_out_discards Int64,
		if_out_errors Int64
	)
	ENGINE = MergeTree
	ORDER BY tuple()`,
		c.dbName, c.tableName)
	return c.conn.Exec(ctx, stm)
}

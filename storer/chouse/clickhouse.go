package chouse

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"strconv"

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
	c.logger.Info("enqueue metric to writ to clickhouse", zap.Any("hostname", metric.Hostname), zap.Any("device", metric.SysName))
	c.enqueue(metric)
	return
}

func (c *ClickhouseClient) enqueue(flow *models.SnmpInterfaceMetrics) {
	c.queue <- flow
}

func (c *ClickhouseClient) StartQueue(ctx context.Context, errGroup *errgroup.Group) error {
	conStr := os.Getenv("CLICKHOUSE_CONCURRENCY")
	concurrency := 10
	if conStr != "" {
		var err error
		concurrency, err = strconv.Atoi(conStr)
		if err != nil {
			return err
		}
	}
	c.logger.Info("starting worker pool", zap.Any("workers", concurrency))
	for i := 0; i < concurrency; i++ {
		errGroup.Go(func() error {
			for job := range c.queue {
				job := job
				if err := c.worker(ctx, job); err != nil {
					return err
				}
			}
			return nil
		})
	}

	return nil
}

func (c *ClickhouseClient) worker(ctx context.Context, job *models.SnmpInterfaceMetrics) error {
	c.logger.Info("starting a clickhouse insert worker")
	select {
	case <-ctx.Done():
		c.logger.Info("clickhouse worker is shutting down")
		return nil
	default:
		c.logger.Info("clickhouse insert received a job to process", zap.Any("device", job.Hostname))
		c.Insert([]*models.SnmpInterfaceMetrics{job})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
}

func (c *ClickhouseClient) Insert(metrics []*models.SnmpInterfaceMetrics) error {
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
				metric.Time,
				metric.SysName,
				metric.Hostname,
				metric.SysDescr,
				metric.Hardware,
				metric.OS,
				metric.Serial,
				metric.ObjectID,
				metric.Uptime,
				metric.Location,
				metric.Lat,
				metric.Lng,

				counters.Neighbour,
				counters.IfAlias,
				counters.IfName,
				counters.IfType,
				counters.Mtu,
				counters.Speed,
				counters.MacAddress,
				counters.AdminStatus,
				counters.OperStatus,

				counters.Counters["ifInMulticastPkts"].Uint64(),
				counters.Counters["ifInBroadcastPkts"].Uint64(),
				counters.Counters["ifOutMulticastPkts"].Uint64(),
				counters.Counters["ifOutBroadcastPkts"].Uint64(),
				counters.Counters["ifHCInOctets"].Uint64(),
				counters.Counters["ifHCInUcastPkts"].Uint64(),
				counters.Counters["ifHCInMulticastPkts"].Uint64(),
				counters.Counters["ifHCInBroadcastPkts"].Uint64(),
				counters.Counters["ifHCOutOctets"].Uint64(),
				counters.Counters["ifHCOutUcastPkts"].Uint64(),
				counters.Counters["ifHCOutMulticastPkts"].Uint64(),
				counters.Counters["ifHCOutBroadcastPkts"].Uint64(),
				counters.Counters["ifHighSpeed"].Uint64(),
				counters.Counters["ifCounterDiscontinuityTime"].Uint64(),
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
		sys_descr VARCHAR(255),
		hardware VARCHAR(255),
		os VARCHAR(255),
		serial VARCHAR(255),
		object_id VARCHAR(255),
		uptime Int64,
		location VARCHAR(255),
		lat Float64,
		lng Float64,

		neighbour VARCHAR(255),
		if_alias VARCHAR(255),
		if_name VARCHAR(255),
		if_type Int32,
		mtu Int64,
		speed Int64,
		mac_address VARCHAR(255),
		admin_status Bool,
		oper_status Bool,
		if_in_multicast_pkts UInt64,
		if_in_broadcast_pkts UInt64,
		if_out_multicast_pkts UInt64,
		if_out_broadcast_pkts UInt64,
		if_hcin_octets UInt64,
		if_hcin_ucast_pkts UInt64,
		if_hcin_multicast_pkts UInt64,
		if_hcin_broadcast_pkts UInt64,
		if_hcout_octets UInt64,
		if_hcout_ucast_pkts  UInt64,
		if_hcout_multicast_pkts  UInt64,
		if_hcout_broadcast_pkts  UInt64,
		if_high_speed UInt64,
		if_counter_discontinuity_time UInt64,
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

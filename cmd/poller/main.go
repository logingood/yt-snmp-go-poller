package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/logingood/yt-snmp-go-poller/config"
	"github.com/logingood/yt-snmp-go-poller/devices/sql"
	"github.com/logingood/yt-snmp-go-poller/internal/lgr"
	"github.com/logingood/yt-snmp-go-poller/models"
	"github.com/logingood/yt-snmp-go-poller/storer/interfaces/iface_chouse"
	"github.com/logingood/yt-snmp-go-poller/worker"
	"github.com/sethvargo/go-envconfig"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func main() {
	logger := lgr.InitializeLogger()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cfg config.FromEnv
	if err := envconfig.Process(ctx, &cfg); err != nil {
		logger.Fatal("cannot read config", zap.Error(err))
		os.Exit(1)
	}

	// handle ctrl + c
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	defer func() {
		signal.Stop(c)
		cancel()
	}()

	go func() {
		select {
		case <-c:
			cancel()
		case <-ctx.Done():
		}
	}()

	db, err := sqlx.Connect("mysql", getConnStringFromCfg(&cfg))
	if err != nil {
		logger.Error("error create mysql conn", zap.Error(err))
		os.Exit(1)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		logger.Error("db did not ping", zap.Error(err))
		os.Exit(1)
	}

	dbClient := sql.New(db, logger)

	ifaceConn, err := clickhouse.Open(getClickHouseConn(&cfg))

	storerGroup, sctx := errgroup.WithContext(ctx)
	storer := iface_chouse.New(logger, ifaceConn, &cfg)
	if err := storer.InitDb(sctx); err != nil {
		logger.Error("error init db", zap.Error(err))
		os.Exit(1)
	}
	storer.StartQueue(sctx, storerGroup)

	offset, max := getWorkerRangeAndOfset(logger)

	workerGroup, wctx := errgroup.WithContext(ctx)
	q := worker.New(logger, dbClient, getInterval(logger), func(snmpMap *models.SnmpInterfaceMetrics) error {
		return storer.Insert([]*models.SnmpInterfaceMetrics{snmpMap})
	}, workerGroup, getWorkersNum(logger), getWorkersNum(logger), offset, max)
	q.StartWorkerPool(wctx)

	group, qctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return q.StartDispatcher(qctx)
	})

	if err := group.Wait(); err != nil {
		logger.Error("error occurred", zap.Error(err))
	} else {
		logger.Error("have a jolly day")
	}
}

func getWorkersNum(logger *zap.Logger) int {
	numOfWorkers := 0
	numberOfWorkersStr := os.Getenv("WORKERS_NUM")
	if numberOfWorkersStr == "" {
		numOfWorkers = 10
	} else {
		var err error
		numOfWorkers, err = strconv.Atoi(numberOfWorkersStr)
		if err != nil {
			logger.Fatal("number of workers must be a number", zap.Any("WORKERS_NUM", numberOfWorkersStr), zap.Error(err))
			panic(err)
		}
	}

	return numOfWorkers
}

func getInterval(logger *zap.Logger) time.Duration {
	var interval time.Duration
	intervalStr := os.Getenv("POLLING_INTERVAL_SECONDS")
	if intervalStr == "" {
		interval = time.Minute * 1
	} else {
		intervalInt, err := strconv.Atoi(intervalStr)
		if err != nil {
			logger.Fatal("interval minutes must be a number", zap.Any("POLLING_INTERVAL_SECONDS", intervalStr), zap.Error(err))
			panic(err)
		}

		interval = time.Second * time.Duration(intervalInt)
	}

	return interval
}

func getWorkerRangeAndOfset(logger *zap.Logger) (int, int) {
	offset := 0
	max := 1000

	workerOffset := os.Getenv("WORKER_OFFSET")
	if workerOffset != "" {
		var err error
		offset, err = strconv.Atoi(workerOffset)
		if err != nil {
			logger.Fatal("number of workers must be a number", zap.Any("WORKERS_OFFSET", workerOffset), zap.Error(err))
			panic(err)
		}
	}
	workerRange := os.Getenv("WORKER_RANGE")
	if workerRange != "" {
		var err error
		max, err = strconv.Atoi(workerRange)
		if err != nil {
			logger.Fatal("number of workers must be a number", zap.Any("WORKERS_RANGE", workerRange), zap.Error(err))
			panic(err)
		}
	}

	return offset, max
}

func getConnStringFromCfg(cfg *config.FromEnv) string {
	connString := fmt.Sprintf("%s:%s@(%s:%s)/%s", cfg.DbUsername, cfg.DbPassword, cfg.DbHost, cfg.DbPort, cfg.DbName)

	return connString
}

func getClickHouseConn(cfg *config.FromEnv) *clickhouse.Options {
	return &clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%s", cfg.ClickhouseAddr, cfg.ClickhousePort)},
		Auth: clickhouse.Auth{
			Database: cfg.ClickhouseDb,
			Username: cfg.ClickhouseUsername,
			Password: cfg.ClickhousePassword,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	}
}

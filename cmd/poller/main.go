package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/logingood/yt-snmp-go-poller/devices/sql"
	"github.com/logingood/yt-snmp-go-poller/internal/lgr"
	"github.com/logingood/yt-snmp-go-poller/models"
	"github.com/logingood/yt-snmp-go-poller/storer/chouse"
	"github.com/logingood/yt-snmp-go-poller/worker"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func main() {
	logger := lgr.InitializeLogger()

	dbUser := os.Getenv("DB_USERNAME")
	dbPass := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	connString := fmt.Sprintf("%s:%s@(%s:%s)/%s", dbUser, dbPass, dbHost, dbPort, dbName)
	db, err := sqlx.Connect("mysql", connString)
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clickDbName := os.Getenv("CLICKHOUSE_DB")
	clickTableName := os.Getenv("CLICKHOUSE_TABLENAME")

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%s", os.Getenv("CLICKHOUSE_ADDR"), os.Getenv("CLICKHOUSE_PORT"))},
		Auth: clickhouse.Auth{
			Database: clickDbName,
			Username: os.Getenv("CLICKHOUSE_USERNAME"),
			Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	})

	storerGroup, sctx := errgroup.WithContext(ctx)
	storer := chouse.New(logger, conn, 100, clickDbName, clickTableName, 1)
	if err := storer.InitDb(sctx); err != nil {
		logger.Error("error init db", zap.Error(err))
	}
	storer.StartQueue(sctx, storerGroup)

	workerGroup, wctx := errgroup.WithContext(ctx)
	q := worker.New(logger, dbClient, getInterval(logger), func(snmpMap *models.SnmpInterfaceMetrics) error {
		return storer.Insert([]*models.SnmpInterfaceMetrics{snmpMap})
	}, workerGroup, getWorkersNum(logger), getWorkersNum(logger))
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

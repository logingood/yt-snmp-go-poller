package main

import (
	"context"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/logingood/yt-snmp-go-poller/devices/sql"
	"github.com/logingood/yt-snmp-go-poller/internal/lgr"
	"github.com/logingood/yt-snmp-go-poller/models"
	"github.com/logingood/yt-snmp-go-poller/snmp"
	"go.uber.org/zap"
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

	ctx := context.Background()
	devices, err := dbClient.ListDevices(ctx)

	for _, dev := range devices {
		s := snmp.New(&dev, logger)

		snmpMap := &models.SnmpInterfaceMetrics{}

		poller := snmp.Compose(
			// do something with the device
			func(snmpMap *models.SnmpInterfaceMetrics) error {
				logger.Info("device map", zap.Any("map", snmpMap))
				return nil
			},
			s.SetCounters,
			s.SetIfName,
			s.SetIfAlias,
			s.SetMtu,
			s.SetSpeed,
			s.SetIfAdminStatus,
			s.SetIfOperStatus,
			s.SetMacAddress,
			s.GetInterfacesMap, // always keep at the bottom
		)
		if err := poller(snmpMap); err != nil {
			panic(err)
		}

	}
}

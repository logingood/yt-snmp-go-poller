package sql

import (
	"context"
	"os"

	"github.com/jmoiron/sqlx"
	"github.com/logingood/yt-snmp-go-poller/models"
	"go.uber.org/zap"
)

const ListQuery = `SELECT device_id, hostname, sysName, community, authlevel, authname, authpass, authalgo, cryptopass, cryptoalgo, snmpver, port, transport,  bgpLocalAs, sysObjectID, sysDescr, sysContact, version, hardware, features, os, status from devices;`

type Client struct {
	db     *sqlx.DB
	logger *zap.Logger
}

func New(db *sqlx.DB, logger *zap.Logger) *Client {
	return &Client{
		db:     db,
		logger: logger,
	}
}

func (c *Client) ListDevices(ctx context.Context) ([]models.Device, error) {
	var devices []models.Device
	// currently we have 1000 devices, what would happen when there's 10k ?
	// TODO fixme
	query := os.Getenv("QUERY")
	if query == "" {
		query = ListQuery
	}
	err := c.db.SelectContext(ctx, &devices, query)
	if err != nil {
		c.logger.Error("error list devices", zap.Error(err))
	}
	return devices, err
}

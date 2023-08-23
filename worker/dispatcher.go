package worker

import (
	"context"
	"time"

	"github.com/logingood/yt-snmp-go-poller/devices/sql"
	"github.com/logingood/yt-snmp-go-poller/models"
	"github.com/logingood/yt-snmp-go-poller/snmp"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type Queue struct {
	logger     *zap.Logger
	dbClient   *sql.Client
	jobChan    chan *models.Device
	interval   time.Duration
	storer     snmp.DecorateFunc
	eg         *errgroup.Group
	numWorkers int
}

func New(
	logger *zap.Logger,
	dbClient *sql.Client,
	interval time.Duration,
	storer snmp.DecorateFunc,
	eg *errgroup.Group,
	numWorkers int,
) *Queue {
	logger.Info("created new queue")
	jobChan := make(chan *models.Device)
	return &Queue{
		logger:     logger,
		dbClient:   dbClient,
		jobChan:    jobChan,
		interval:   interval,
		storer:     storer,
		numWorkers: numWorkers,
		eg:         eg,
	}
}

func (q *Queue) StartDispatcher(ctx context.Context) error {
	// Create a new ticker with a period of 1 second.
	ticker := time.NewTicker(q.interval)
	q.logger.Info("start dispatcher to run every", zap.Any("interval", q.interval))

	for {
		select {
		case <-ticker.C:
			// TODO cache this call
			q.logger.Info("woke up to list devices")
			devices, err := q.dbClient.ListDevices(ctx)
			if err != nil {
				return err
			}
			q.logger.Info("found devices", zap.Int("devices", len(devices)))
			for _, dev := range devices {
				dev := dev
				q.jobChan <- &dev
			}
		case <-ctx.Done():
			q.logger.Info("stopping dispatcher")
			ticker.Stop()
			return nil
		}
	}
}

func (q *Queue) StartWorkerPool(ctx context.Context) error {
	q.logger.Info("starting worker pool", zap.Any("workers", q.numWorkers))
	for i := 0; i < q.numWorkers; i++ {
		q.eg.Go(func() error {
			if err := q.worker(ctx); err != nil {
				return err
			}
			return nil
		})
	}

	return nil
}

func (q *Queue) worker(ctx context.Context) error {
	q.logger.Info("starting a worker")
	select {
	case <-ctx.Done():
		q.logger.Info("worker is shutting down")
		return nil
	case job := <-q.jobChan:
		q.process(job)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
}

func (q *Queue) process(job *models.Device) error {
	s := snmp.New(job, q.logger)
	snmpMap := &models.SnmpInterfaceMetrics{}

	poller := snmp.Compose(
		// do something with the device
		q.storer,

		// adding snmp properties and counters
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
		return err
	}

	return nil
}

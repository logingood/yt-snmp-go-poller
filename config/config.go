package config

type FromEnv struct {
	PollingIntervalSeconds int    `env:"POLLING_INTERVAL_SECONDS,required"`
	WorkersNum             int    `env:"WORKERS_NUM,required"`
	LogLevel               string `env:"LOG_LEVEL"`

	// Librenms DB credentials
	DbUsername string `env:"DB_USERNAME,required"`
	DbPassword string `env:"DB_PASSWORD,required"`
	DbHost     string `env:"DB_HOST,required"`
	DbPort     string `env:"DB_PORT,required"`
	DbName     string `env:"DB_NAME,required"`

	/* Each SNMP poller has it's own table */
	ClickhouseInterfacesTableName     string `env:"CLICKHOUSE_INTERFACES_TABLE_NAME,required"`
	ClickhouseCpuTableName            string `env:"CLICKHOUSE_CPU_TABLE_NAME"`
	ClickhouseStorageTableName        string `env:"CLICKHOUSE_STORAGE_TABLE_NAME"`
	ClickhouseMemoryTableName         string `env:"CLICKHOUSE_MEMORY_TABLE_NAME"`
	ClickhouseSfpPowerLevelsTableName string `env:"CLICKHOUSE_SFP_POWER_LEVELS_TABLE_NAME"`

	ClickhouseQueueLength    int    `env:"CLICKHOUSE_QUEUE_LENGTH,required"`
	ClickhouseFlushFrequency int    `env:"CLICKHOUSE_FLUSH_FREQUENCY,required"`
	ClickhouseDb             string `env:"CLICKHOUSE_DB,required"`
	ClickhouseUsername       string `env:"CLICKHOUSE_USERNAME,required"`
	ClickhousePassword       string `env:"CLICKHOUSE_PASSWORD,required"`
	ClickhouseAddr           string `env:"CLICKHOUSE_ADDR,required"`
	ClickhousePort           string `env:"CLICKHOUSE_PORT,required"`
}

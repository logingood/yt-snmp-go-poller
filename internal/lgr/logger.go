package lgr

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func newProductionEncoderConfig() zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.EpochTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
}

func InitializeLogger() *zap.Logger {
	var level zapcore.Level
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}
	if err := level.Set(logLevel); err != nil {
		panic(fmt.Sprintf("can't set log level: %s", err.Error()))
	}

	logger, err := zap.Config{
		Encoding:      "json",
		Level:         zap.NewAtomicLevelAt(level),
		OutputPaths:   []string{"stdout"},
		EncoderConfig: newProductionEncoderConfig(),
	}.Build()
	if err != nil {
		panic(fmt.Sprintf("can't initialise the logger: %s", err.Error()))
	}
	return logger
}

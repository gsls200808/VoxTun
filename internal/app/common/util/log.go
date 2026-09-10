package util

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger 全局日志实例（sugared logger，支持 key-value 写法）
var Logger *zap.SugaredLogger

// InitLogger 初始化日志
func InitLogger(level string) error {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "time"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	logger, err := cfg.Build()
	if err != nil {
		return err
	}
	Logger = logger.Sugar()
	return nil
}

// Sync 刷新日志缓冲区
func Sync() {
	if Logger != nil {
		_ = Logger.Sync()
	}
}

package logger

import (
	"context"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

type contextKey string

const LoggerKey = contextKey("logger")

var globalLogger *zap.SugaredLogger

// Init initializes the global logger based on configuration.
// Init 根据配置初始化全局日志记录器。
func Init(cfg LoggingConfig) {
	// Default to stdout if not configured or disabled
	writeSyncer := zapcore.AddSync(os.Stdout)

	if cfg.Enabled && cfg.Path != "" {
		// Create directory if not exists
		dir := filepath.Dir(cfg.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			// Log to stdout if we can't create the directory
			// 如果无法创建目录，则输出到 stdout
			globalLogger = zap.NewExample().Sugar()
			globalLogger.Warnf("[WARN]  Failed to create log directory: %v", err)
		}

		rotator := &lumberjack.Logger{
			Filename:   cfg.Path,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge,
			Compress:   cfg.Compress,
		}
		writeSyncer = zapcore.AddSync(rotator)
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zapcore.NewConsoleEncoder(encoderConfig)

	level := zapcore.InfoLevel
	if cfg.Level == "debug" {
		level = zapcore.DebugLevel
	}

	core := zapcore.NewCore(encoder, writeSyncer, level)
	logger := zap.New(core, zap.AddCaller())
	globalLogger = logger.Sugar()

	globalLogger.Infof("[LOG] Logging initialized (Level: %s, Path: %s)", level, cfg.Path)
}

// Sync flushes any buffered log entries.
// Sync 刷新所有缓存的日志条目。
func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}

// Get returns the logger from context or global logger
// Get 从 Context 或全局日志记录器返回 Logger。
func Get(ctx context.Context) *zap.SugaredLogger {
	if ctx != nil {
		if logger, ok := ctx.Value(LoggerKey).(*zap.SugaredLogger); ok {
			return logger
		}
	}
	if globalLogger == nil {
		// Fallback to basic stdout logger if not initialized
		l, err := zap.NewDevelopment()
		if err != nil {
			// Ultimate fallback: use example logger
			return zap.NewExample().Sugar()
		}
		return l.Sugar()
	}
	return globalLogger
}

// WithContext adds logger to context
// WithContext 将 Logger 添加到 Context。
func WithContext(ctx context.Context, logger *zap.SugaredLogger) context.Context {
	return context.WithValue(ctx, LoggerKey, logger)
}

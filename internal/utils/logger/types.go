package logger

// LoggingConfig defines the configuration for logging.
// LoggingConfig 定义日志配置。
type LoggingConfig struct {
	Enabled bool `yaml:"enabled"`
	// Enabled: 是否启用日志
	Level string `yaml:"level"`
	// Level: 日志级别（debug, info, warn, error）
	Path string `yaml:"path"`
	// Path: 日志文件路径
	MaxSize int `yaml:"max_size"`
	// MaxSize: 轮转前的最大大小（MB）
	MaxBackups int `yaml:"max_backups"`
	// MaxBackups: 保留的旧文件最大数量
	MaxAge int `yaml:"max_age"`
	// MaxAge: 保留旧文件的最大天数
	Compress bool `yaml:"compress"`
	// Compress: 是否压缩旧文件
}

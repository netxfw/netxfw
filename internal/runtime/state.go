package runtime

// Mode indicates the operating mode of the application (e.g., "dp", "agent", or empty for standalone).
// Mode 表示应用程序的运行模式（例如 "dp"、"agent"，Standalone 模式下为空）。
var Mode string

// ConfigPath stores the path to the configuration file provided via CLI flags.
// ConfigPath 存储通过 CLI 标志提供的配置文件路径。
var ConfigPath string

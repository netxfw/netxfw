// Package main provides main functionality.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Config migration tool: YAML to TOML
// 配置迁移工具：YAML 转 TOML

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	inputFile := flag.String("input", "", "Input YAML config file / 输入 YAML 配置文件")
	outputFile := flag.String("output", "", "Output TOML config file (default: same as input with .toml extension) / 输出 TOML 配置文件（默认：与输入同名但扩展名为 .toml）")
	validate := flag.Bool("validate", true, "Validate the converted config / 验证转换后的配置")
	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Usage: yaml2toml -input <yaml-file> [-output <toml-file>] [-validate]")
		fmt.Println("用法: yaml2toml -input <yaml文件> [-output <toml文件>] [-validate]")
		flag.PrintDefaults()
		return fmt.Errorf("input file is required")
	}

	output := *outputFile
	if output == "" {
		ext := filepath.Ext(*inputFile)
		output = (*inputFile)[:len(*inputFile)-len(ext)] + ".toml"
	}

	fmt.Printf("Converting: %s -> %s\n", *inputFile, output)
	fmt.Printf("转换中: %s -> %s\n", *inputFile, output)

	yamlData, err := os.ReadFile(*inputFile)
	if err != nil {
		return fmt.Errorf("error reading input file / 读取输入文件错误: %w", err)
	}

	var config map[string]interface{}
	yamlErr := yaml.Unmarshal(yamlData, &config)
	if yamlErr != nil {
		return fmt.Errorf("error parsing YAML / 解析 YAML 错误: %w", yamlErr)
	}

	outFile, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("error creating output file / 创建输出文件错误: %w", err)
	}
	defer outFile.Close()

	header := `# NetXFW Configuration File / NetXFW 配置文件
# Migrated from YAML format / 从 YAML 格式迁移
# TOML format - Better cross-language support / TOML 格式 - 更好的跨语言支持
#

`
	if _, err := outFile.WriteString(header); err != nil {
		return fmt.Errorf("error writing header / 写入头部错误: %w", err)
	}

	if err := toml.NewEncoder(outFile).Encode(config); err != nil {
		return fmt.Errorf("error encoding TOML / 编码 TOML 错误: %w", err)
	}

	fmt.Printf("✅ Conversion complete / 转换完成\n")
	fmt.Printf("Output file / 输出文件: %s\n", output)

	if *validate {
		fmt.Printf("\nValidating converted config / 验证转换后的配置...\n")
		tomlData, err := os.ReadFile(output)
		if err != nil {
			return fmt.Errorf("error reading converted file / 读取转换后文件错误: %w", err)
		}

		var validatedConfig map[string]interface{}
		if _, err := toml.Decode(string(tomlData), &validatedConfig); err != nil {
			return fmt.Errorf("validation failed / 验证失败: %w", err)
		}

		fmt.Printf("✅ Validation passed / 验证通过\n")
		fmt.Printf("Config sections / 配置节: %d\n", len(validatedConfig))
	}

	return nil
}

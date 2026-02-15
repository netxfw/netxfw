package fileutil

import (
	"os"
	"strings"
)

// ReadLines reads all non-empty lines from a file.
// ReadLines 读取文件中的所有非空行。
func ReadLines(filePath string) ([]string, error) {
	if filePath == "" {
		return nil, nil
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, nil
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines, nil
}

// AppendToFile appends a line to a file if it doesn't already exist.
// AppendToFile 将一行追加到文件（如果尚不存在）。
func AppendToFile(filePath, line string) error {
	if filePath == "" {
		return nil
	}
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Check if already exists (naive check, good for small files)
	// 检查是否已存在（简单的检查，适用于小文件）
	content, err := os.ReadFile(filePath)
	if err == nil && strings.Contains(string(content), line) {
		return nil
	}

	_, err = f.WriteString(line + "\n")
	return err
}

// RemoveFromFile removes a line from a file.
// RemoveFromFile 从文件中移除一行。
func RemoveFromFile(filePath, line string) error {
	if filePath == "" {
		return nil
	}
	input, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(input), "\n")
	var newLines []string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && trimmed != line {
			newLines = append(newLines, trimmed)
		}
	}

	return os.WriteFile(filePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}

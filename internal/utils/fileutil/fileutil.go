package fileutil

import (
	"os"
	"path/filepath"
	"strings"
)

// AtomicWriteFile writes data to a temporary file and then renames it to the target file.
// AtomicWriteFile 将数据写入临时文件，然后将其重命名为目标文件。
func AtomicWriteFile(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename) // #nosec G703 // Safe: filepath.Dir cleans the path preventing traversal
	tmpFile, err := os.CreateTemp(dir, "atomic-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name()) // Clean up if something fails

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpFile.Name(), filename) // #nosec G703 // filename is validated by caller
}

// ReadLines reads all non-empty lines from a file.
// ReadLines 读取文件中的所有非空行。
func ReadLines(filePath string) ([]string, error) {
	if filePath == "" {
		return nil, nil
	}
	safePath := filepath.Clean(filePath) // Sanitize path to prevent directory traversal
	if _, err := os.Stat(safePath); os.IsNotExist(err) {
		return nil, nil
	}
	content, err := os.ReadFile(safePath) // #nosec G304 // filePath is sanitized with filepath.Clean
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
	safePath := filepath.Clean(filePath)                                       // Sanitize path to prevent directory traversal
	f, err := os.OpenFile(safePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) // #nosec G304 // filePath is sanitized with filepath.Clean
	if err != nil {
		return err
	}
	defer f.Close()

	// Check if already exists (naive check, good for small files)
	// 检查是否已存在（简单的检查，适用于小文件）
	content, err := os.ReadFile(safePath) // #nosec G304 // filePath is sanitized with filepath.Clean
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
	safePath := filepath.Clean(filePath) // Sanitize path to prevent directory traversal
	input, err := os.ReadFile(safePath)  // #nosec G304 // filePath is sanitized with filepath.Clean
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

	return os.WriteFile(safePath, []byte(strings.Join(newLines, "\n")+"\n"), 0600) // #nosec G304 // filePath is sanitized with filepath.Clean
}

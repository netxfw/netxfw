package core

import (
	"bufio"
	"strings"
)

var askConfirmationReader *bufio.Reader

// SetConfirmationReader sets the reader for confirmation prompts.
// SetConfirmationReader 设置确认提示的读取器（主要用于测试）。
func SetConfirmationReader(r *bufio.Reader) {
	askConfirmationReader = r
}

// AskConfirmation parses a yes/no answer from the configured reader.
// AskConfirmation 从配置的读取器解析是/否答案。
// Terminal prompting belongs to the caller layer; this function only parses input.
func AskConfirmation(_ string) bool {
	if askConfirmationReader == nil {
		return false
	}

	response, err := askConfirmationReader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

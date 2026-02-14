package core

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var askConfirmationReader *bufio.Reader

// SetConfirmationReader sets the reader for confirmation prompts.
// Useful for testing.
func SetConfirmationReader(r *bufio.Reader) {
	askConfirmationReader = r
}

// AskConfirmation prompts the user for a yes/no answer.
// AskConfirmation 提示用户输入是/否。
func AskConfirmation(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)

	reader := askConfirmationReader
	if reader == nil {
		reader = bufio.NewReader(os.Stdin)
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

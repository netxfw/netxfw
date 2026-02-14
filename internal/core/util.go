package core

import (
	"fmt"
	"strings"
)

/**
 * AskConfirmation asks the user for a y/n confirmation.
 * AskConfirmation 询问用户是否确认 (y/n)。
 */
func AskConfirmation(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

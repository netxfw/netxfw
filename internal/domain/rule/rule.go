package rule

import "fmt"

// Action captures allow/deny rule semantics.
type Action uint8

const (
	ActionDeny Action = iota
	ActionAllow
)

// Rule is the minimal domain representation of a firewall rule.
type Rule struct {
	Selector Selector
	Action   Action
}

func NewRule(selector Selector, action Action) (Rule, error) {
	if err := ValidateAction(action); err != nil {
		return Rule{}, err
	}
	return Rule{
		Selector: selector,
		Action:   action,
	}, nil
}

func ParseAction(raw string) (Action, error) {
	switch raw {
	case "allow":
		return ActionAllow, nil
	case "deny":
		return ActionDeny, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrInvalidAction, raw)
	}
}

func ValidateAction(action Action) error {
	if action != ActionDeny && action != ActionAllow {
		return fmt.Errorf("%w: %d", ErrInvalidAction, action)
	}
	return nil
}

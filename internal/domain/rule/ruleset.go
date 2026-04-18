package rule

import "fmt"

// RuleSet is the minimal aggregate used by import/export and command flows.
type RuleSet struct {
	rules []Rule
	keys  map[string]struct{}
}

func NewRuleSet(rules ...Rule) (RuleSet, error) {
	set := RuleSet{
		rules: make([]Rule, 0, len(rules)),
		keys:  make(map[string]struct{}, len(rules)),
	}
	for _, rule := range rules {
		if err := set.Add(rule); err != nil {
			return RuleSet{}, err
		}
	}
	return set, nil
}

func (s *RuleSet) Add(rule Rule) error {
	if s.keys == nil {
		s.keys = make(map[string]struct{})
	}

	key := fmt.Sprintf("%s#%d", rule.Selector.Key(), rule.Action)
	if _, exists := s.keys[key]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateRule, key)
	}

	s.keys[key] = struct{}{}
	s.rules = append(s.rules, rule)
	return nil
}

func (s RuleSet) Len() int {
	return len(s.rules)
}

func (s RuleSet) Rules() []Rule {
	return append([]Rule(nil), s.rules...)
}

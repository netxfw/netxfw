package storage

import "errors"

var ErrNotImplemented = errors.New("storage method not implemented")

// RedisStore - Future implementation
// RedisStore - 未来实现
type RedisStore struct {
	Addr     string
	Password string
	DB       int
}

func (s *RedisStore) AddIP(ruleType RuleType, cidr string) error    { return ErrNotImplemented }
func (s *RedisStore) RemoveIP(ruleType RuleType, cidr string) error { return ErrNotImplemented }
func (s *RedisStore) AddIPPortRule(rule IPPortRule) error           { return ErrNotImplemented }
func (s *RedisStore) RemoveIPPortRule(cidr string, port uint16, proto string) error {
	return ErrNotImplemented
}
func (s *RedisStore) LoadAll() ([]string, []string, []IPPortRule, error) {
	return nil, nil, nil, ErrNotImplemented
}

// SQLiteStore - Future implementation
// SQLiteStore - 未来实现
type SQLiteStore struct {
	Path string
}

func (s *SQLiteStore) AddIP(ruleType RuleType, cidr string) error    { return ErrNotImplemented }
func (s *SQLiteStore) RemoveIP(ruleType RuleType, cidr string) error { return ErrNotImplemented }
func (s *SQLiteStore) AddIPPortRule(rule IPPortRule) error           { return ErrNotImplemented }
func (s *SQLiteStore) RemoveIPPortRule(cidr string, port uint16, proto string) error {
	return ErrNotImplemented
}
func (s *SQLiteStore) LoadAll() ([]string, []string, []IPPortRule, error) {
	return nil, nil, nil, ErrNotImplemented
}

// PGStore - Future implementation (PostgreSQL)
// PGStore - 未来实现 (PostgreSQL)
type PGStore struct {
	ConnStr string
}

func (s *PGStore) AddIP(ruleType RuleType, cidr string) error    { return ErrNotImplemented }
func (s *PGStore) RemoveIP(ruleType RuleType, cidr string) error { return ErrNotImplemented }
func (s *PGStore) AddIPPortRule(rule IPPortRule) error           { return ErrNotImplemented }
func (s *PGStore) RemoveIPPortRule(cidr string, port uint16, proto string) error {
	return ErrNotImplemented
}
func (s *PGStore) LoadAll() ([]string, []string, []IPPortRule, error) {
	return nil, nil, nil, ErrNotImplemented
}

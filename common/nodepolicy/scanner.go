package nodepolicy

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/sagernet/sing-box/adapter"

	"github.com/google/cel-go/cel"
)

// Scanner evaluates the original string-valued BlockScanner CEL expression.
// @author lyt
// @date 2026-10-29
type Scanner struct {
	program cel.Program
}

func NewScanner(expression string) (*Scanner, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return nil, nil
	}
	variables := []cel.EnvOption{cel.Variable("uid", cel.UintType)}
	for _, name := range []string{"source", "dest", "fingerprint", "protocol", "network", "inbound", "domain"} {
		variables = append(variables, cel.Variable(name, cel.StringType))
	}
	environment, err := cel.NewEnv(variables...)
	if err != nil {
		return nil, err
	}
	ast, issues := environment.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}
	if !ast.OutputType().IsExactType(cel.StringType) {
		return nil, fmt.Errorf("BlockScanner output must be string, got %s", ast.OutputType())
	}
	program, err := environment.Program(ast)
	if err != nil {
		return nil, err
	}
	return &Scanner{program: program}, nil
}

func (s *Scanner) Check(metadata *adapter.InboundContext, fingerprint string, uid uint64) (string, error) {
	if s == nil {
		return "", nil
	}
	value, _, err := s.program.Eval(map[string]any{
		"source": metadata.Source.String(), "dest": metadata.Destination.String(),
		"fingerprint": fingerprint, "protocol": metadata.Protocol, "network": metadata.Network,
		"inbound": metadata.Inbound, "domain": metadata.Domain, "uid": uid,
	})
	if err != nil {
		return "", err
	}
	native, err := value.ConvertToNative(reflect.TypeFor[string]())
	if err != nil {
		return "", err
	}
	return native.(string), nil
}

// MustCheck preserves the original error policy: evaluation errors produce no scanner rejection.
func (s *Scanner) MustCheck(metadata *adapter.InboundContext, fingerprint string, uid uint64) string {
	value, err := s.Check(metadata, fingerprint, uid)
	if err != nil {
		return ""
	}
	return value
}

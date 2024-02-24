package internal

import (
	"fmt"
	"github.com/anderslauri/open-iap/internal/cache"
	"github.com/google/cel-go/cel"
)

type celParams map[string]any

// celVars are variables supported for parsing of IAM-conditional expression given context of Aware Proxy,
// assuming more are required. Those should be appended here below. The conditional parser will use these.
var celVars = func() *cel.Env {
	// Based on: https://cloud.google.com/iam/docs/conditions-overview#example-url-host-path
	env, _ := cel.NewEnv(
		cel.Variable("request.path", cel.StringType),
		cel.Variable("request.host", cel.StringType),
		cel.Variable("request.time", cel.TimestampType),
	)
	return env
}()

// Cache for compiled programs.
var prgCache = cache.NewCopyOnWriteCache()

func compileProgram(expression string) (cel.Program, error) {
	if p, ok := prgCache.Get(expression); ok {
		return p.(cel.Program), nil
	}
	ast, issues := celVars.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("type-check error: %s", issues.Err())
	}
	prg, err := celVars.Program(ast)
	if err != nil {
		return nil, err
	}
	// Don't block the caller when writing to cache.
	go prgCache.Set(expression, prg)
	return prg, err
}

func doesConditionalExpressionEvaluateToTrue(expression string, params celParams) (bool, error) {
	prg, err := compileProgram(expression)
	if err != nil {
		return false, err
	}
	out, _, err := prg.Eval(map[string]any(params))
	if err != nil {
		return false, err
	} else if val, ok := out.Value().(bool); val && ok == true {
		return true, nil
	}
	return false, nil
}

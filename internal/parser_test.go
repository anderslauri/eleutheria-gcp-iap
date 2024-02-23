package internal

import (
	"testing"
	"time"
)

func params(requestPath, requestHost string, requestTime time.Time) map[string]any {
	return map[string]any{
		"request.path": requestPath,
		"request.host": requestHost,
		"request.time": requestTime,
	}
}

var defaultLocation, _ = time.LoadLocation("Europe/Berlin")

// https://cloud.google.com/iam/docs/conditions-overview
func TestExpressionParser(t *testing.T) {
	var defaultParams = params("/something", "myurl.com", time.Now())

	var tests = []struct {
		name            string
		condition       string
		params          map[string]any
		isConditionTrue bool
		expectedError   error
	}{
		{"TestConditionEvaluateToTrue", "request.path.endsWith(\"/something\")", defaultParams, true, nil},
		{"TestConditionEvaluateToFalse", "request.path.endsWith(\"something else\")", params("/not", "myhost.com", time.Now()), false, nil},
		{"TestConditionWithTimestampEvaluateToTrue", "request.time > timestamp(\"2021-01-01T00:00:00Z\")", params("/not", "myhost.com", time.Now()), true, nil},
		{"TestConditionWithInBetweenRangeEvaluateToTrue",
			"request.time.getHours(\"Europe/Berlin\") >= 9 &&" +
				" request.time.getHours(\"Europe/Berlin\") <= 17 && " +
				"request.time.getDayOfWeek(\"Europe/Berlin\") >= 1 && " +
				"request.time.getDayOfWeek(\"Europe/Berlin\") <= 5",
			params("", "",
				// This is Tuesday.
				time.Date(2024, 02, 06, 12, 00, 00, 00, defaultLocation)),
			true, nil},
		{"TestConditionWithInBetweenRangeEvaluateToFalse",
			"request.time.getHours(\"Europe/Berlin\") >= 9 &&" +
				" request.time.getHours(\"Europe/Berlin\") <= 17 && " +
				"request.time.getDayOfWeek(\"Europe/Berlin\") >= 1 && " +
				"request.time.getDayOfWeek(\"Europe/Berlin\") <= 5",
			params("", "",
				// This is Sunday.
				time.Date(2024, 02, 11, 12, 00, 00, 00, defaultLocation)),
			false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isTrue, err := doesConditionalExpressionEvaluateToTrue(tt.condition, tt.params)
			if err != nil {
				t.Fatalf("Test %s returned error %s", tt.name, err)
			} else if tt.isConditionTrue && !isTrue {
				t.Fatalf("Test %s is expected to be true.", tt.name)
			} else if !tt.isConditionTrue && isTrue {
				t.Fatalf("Test %s is expected not to be true.", tt.name)
			}
		})
	}
}

func BenchmarkConditionalParserWithCache(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = doesConditionalExpressionEvaluateToTrue(
			"request.path.endsWith(\"/something\")",
			params("/something", "myurl.com", time.Now()))
	}
}

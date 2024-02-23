// Code generated from Pkl module `ApplicationConfig`. DO NOT EDIT.
package loglevel

import (
	"encoding"
	"fmt"
)

type LogLevel string

const (
	INFO    LogLevel = "INFO"
	WARNING LogLevel = "WARNING"
	DEBUG   LogLevel = "DEBUG"
	ERROR   LogLevel = "ERROR"
	TRACE   LogLevel = "TRACE"
)

// String returns the string representation of LogLevel
func (rcv LogLevel) String() string {
	return string(rcv)
}

var _ encoding.BinaryUnmarshaler = new(LogLevel)

// UnmarshalBinary implements encoding.BinaryUnmarshaler for LogLevel.
func (rcv *LogLevel) UnmarshalBinary(data []byte) error {
	switch str := string(data); str {
	case "INFO":
		*rcv = INFO
	case "WARNING":
		*rcv = WARNING
	case "DEBUG":
		*rcv = DEBUG
	case "ERROR":
		*rcv = ERROR
	case "TRACE":
		*rcv = TRACE
	default:
		return fmt.Errorf(`illegal: "%s" is not a valid LogLevel`, str)
	}
	return nil
}

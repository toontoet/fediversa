package logging

import (
	"log"
	"os"
)

var (
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
)

func init() {
	// Initialize loggers to write to standard output/error
	// Includes date, time, and source file/line number for context.
	// TODO: Make log level configurable via config
	infoLogger = log.New(os.Stdout, "INFO:  ", log.Ldate|log.Ltime|log.Lshortfile)
	warnLogger = log.New(os.Stdout, "WARN:  ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// Info logs informational messages.
func Info(format string, v ...interface{}) {
	infoLogger.Printf(format, v...)
}

// Warn logs warning messages.
func Warn(format string, v ...interface{}) {
	warnLogger.Printf(format, v...)
}

// Error logs error messages.
func Error(format string, v ...interface{}) {
	errorLogger.Printf(format, v...)
}

// Fatal logs error messages and exits the program with status 1.
func Fatal(format string, v ...interface{}) {
	errorLogger.Fatalf(format, v...)
	// No return needed, Fatalf exits the program
}

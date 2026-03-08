package output

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

type Loggers struct {
	Info      *log.Logger
	Debug     *log.Logger
	resultFile *os.File
	debugFile  *os.File
}

func New(outputDir string, debug bool) (*Loggers, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir %s: %w", outputDir, err)
	}

	ts := time.Now().Format("060102_150405")
	resultPath := filepath.Join(outputDir, fmt.Sprintf("result_paasau_%s.log", ts))
	debugPath := filepath.Join(outputDir, fmt.Sprintf("debug_paasau_%s.log", ts))

	resultFile, err := os.Create(resultPath)
	if err != nil {
		return nil, fmt.Errorf("create result log %s: %w", resultPath, err)
	}

	debugFile, err := os.Create(debugPath)
	if err != nil {
		resultFile.Close()
		return nil, fmt.Errorf("create debug log %s: %w", debugPath, err)
	}

	infoLogger := log.New(io.MultiWriter(os.Stdout, resultFile), "", log.Ldate|log.Ltime)
	debugWriter := io.Writer(io.Discard)
	if debug {
		debugWriter = io.MultiWriter(os.Stdout, debugFile)
	}
	debugLogger := log.New(debugWriter, "DEBUG: ", log.Ldate|log.Ltime)

	return &Loggers{
		Info:       infoLogger,
		Debug:      debugLogger,
		resultFile: resultFile,
		debugFile:  debugFile,
	}, nil
}

func (l *Loggers) Close() error {
	var firstErr error
	if l.resultFile != nil {
		if err := l.resultFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if l.debugFile != nil {
		if err := l.debugFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

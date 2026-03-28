package tests

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	liveEnvLoadOnce sync.Once
	liveEnvLoadErr  error
)

func ensureLiveTestEnvLoaded() error {
	liveEnvLoadOnce.Do(func() {
		workingDir, err := os.Getwd()
		if err != nil {
			liveEnvLoadErr = err
			return
		}

		dotEnvPath, found := findNearestDotEnvFile(workingDir)
		if !found {
			return
		}

		liveEnvLoadErr = loadEnvFileIfUnset(dotEnvPath)
	})

	return liveEnvLoadErr
}

func findNearestDotEnvFile(startDir string) (string, bool) {
	currentDir := startDir
	for {
		candidate := filepath.Join(currentDir, ".env")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}

		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			break
		}
		currentDir = parentDir
	}

	return "", false
}

func loadEnvFileIfUnset(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}

		value = sanitizeEnvValue(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		if setErr := os.Setenv(key, value); setErr != nil {
			return setErr
		}
	}

	return scanner.Err()
}

func sanitizeEnvValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}

	inSingleQuote := false
	inDoubleQuote := false
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '#':
			if inSingleQuote || inDoubleQuote {
				continue
			}
			if index == 0 {
				return ""
			}
			previous := value[index-1]
			if previous == ' ' || previous == '\t' {
				return strings.TrimSpace(value[:index])
			}
		}
	}

	return strings.TrimSpace(value)
}

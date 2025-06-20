package chacha20poly1305

import (
	"math"
	"sync"
	"time"
)

type RetryConfig struct {
	MaxRetries      int
	InitialDelay    time.Duration
	MaxDelay        time.Duration
	BackoffFactor   float64
	EnableJitter    bool
	TimeoutPerRetry time.Duration
}

type RetryResult struct {
	Success      bool
	AttemptCount int
	TotalTime    time.Duration
	LastError    error
}

type RetryStats struct {
	TotalAttempts   int64
	SuccessCount    int64
	FailureCount    int64
	AverageRetries  float64
	TotalRetryTime  time.Duration
	LastFailureTime time.Time
	mutex           sync.RWMutex
}

var (
	defaultRetryConfig = RetryConfig{
		MaxRetries:      3,
		InitialDelay:    500 * time.Millisecond,
		MaxDelay:        10 * time.Second,
		BackoffFactor:   2.0,
		EnableJitter:    true,
		TimeoutPerRetry: 30 * time.Second,
	}

	globalRetryStats = &RetryStats{}
)

func (config *RetryConfig) calculateDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}

	delay := float64(config.InitialDelay) * math.Pow(config.BackoffFactor, float64(attempt-1))

	if delay > float64(config.MaxDelay) {
		delay = float64(config.MaxDelay)
	}

	finalDelay := time.Duration(delay)

	if config.EnableJitter && finalDelay > 0 {
		jitter := float64(finalDelay) * 0.25 * (2*math.Abs(float64(time.Now().UnixNano()%1000))/1000 - 1)
		finalDelay = time.Duration(float64(finalDelay) + jitter)

		if finalDelay < 0 {
			finalDelay = config.InitialDelay
		}
	}

	return finalDelay
}

func shouldRetry(err error, attempt int, config *RetryConfig) bool {
	if err == nil {
		return false
	}

	if attempt >= config.MaxRetries {
		return false
	}

	errStr := err.Error()

	networkErrors := []string{
		"connection timeout",
		"connection reset",
		"network is unreachable",
		"no such host",
		"connection refused",
		"i/o timeout",
		"context deadline exceeded",
	}

	for _, netErr := range networkErrors {
		if contains(errStr, netErr) {
			return true
		}
	}

	if contains(errStr, "5") && (contains(errStr, "500") || contains(errStr, "502") ||
		contains(errStr, "503") || contains(errStr, "504")) {
		return true
	}

	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(len(substr) == 0 || s[len(s)-len(substr):] == substr ||
			s[:len(substr)] == substr ||
			findInString(s, substr))
}

func findInString(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func executeWithRetry(operation func() error, config *RetryConfig) *RetryResult {
	if config == nil {
		config = &defaultRetryConfig
	}

	startTime := time.Now()
	var lastError error

	for attempt := 1; attempt <= config.MaxRetries+1; attempt++ {
		globalRetryStats.recordAttempt()

		err := operation()

		if err == nil {
			result := &RetryResult{
				Success:      true,
				AttemptCount: attempt,
				TotalTime:    time.Since(startTime),
				LastError:    nil,
			}
			globalRetryStats.recordSuccess(attempt)
			return result
		}

		lastError = err

		if !shouldRetry(err, attempt, config) {
			break
		}

		if attempt <= config.MaxRetries {
			delay := config.calculateDelay(attempt)
			time.Sleep(delay)
		}
	}

	result := &RetryResult{
		Success:      false,
		AttemptCount: config.MaxRetries + 1,
		TotalTime:    time.Since(startTime),
		LastError:    lastError,
	}

	globalRetryStats.recordFailure(lastError)
	return result
}

func (stats *RetryStats) recordAttempt() {
	stats.mutex.Lock()
	defer stats.mutex.Unlock()
	stats.TotalAttempts++
}

func (stats *RetryStats) recordSuccess(attempts int) {
	stats.mutex.Lock()
	defer stats.mutex.Unlock()
	stats.SuccessCount++

	totalOperations := stats.SuccessCount + stats.FailureCount
	if totalOperations > 0 {
		stats.AverageRetries = float64(stats.TotalAttempts) / float64(totalOperations)
	}
}

func (stats *RetryStats) recordFailure(err error) {
	stats.mutex.Lock()
	defer stats.mutex.Unlock()
	stats.FailureCount++
	stats.LastFailureTime = time.Now()

	totalOperations := stats.SuccessCount + stats.FailureCount
	if totalOperations > 0 {
		stats.AverageRetries = float64(stats.TotalAttempts) / float64(totalOperations)
	}
}

func GetRetryStats() map[string]interface{} {
	globalRetryStats.mutex.RLock()
	defer globalRetryStats.mutex.RUnlock()

	return map[string]interface{}{
		"total_attempts":    globalRetryStats.TotalAttempts,
		"success_count":     globalRetryStats.SuccessCount,
		"failure_count":     globalRetryStats.FailureCount,
		"average_retries":   globalRetryStats.AverageRetries,
		"total_retry_time":  globalRetryStats.TotalRetryTime,
		"last_failure_time": globalRetryStats.LastFailureTime,
		"success_rate":      calculateSuccessRate(globalRetryStats.SuccessCount, globalRetryStats.FailureCount),
	}
}

func calculateSuccessRate(success, failure int64) float64 {
	total := success + failure
	if total == 0 {
		return 0.0
	}
	return float64(success) / float64(total) * 100.0
}

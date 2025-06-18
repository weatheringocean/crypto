package chacha20poly1305

import (
	"sync"
	"time"
)

var (
	metricsCollector struct {
		operationLatency  map[string][]time.Duration
		throughputMetrics map[string]*throughputInfo
		errorCounts       map[string]int64
		sessionMetrics    *sessionInfo
		mutex             sync.RWMutex
		initialized       bool
	}
)

type throughputInfo struct {
	BytesProcessed int64     `json:"bytes_processed"`
	OperationCount int64     `json:"operation_count"`
	StartTime      time.Time `json:"start_time"`
	LastUpdate     time.Time `json:"last_update"`
}

type sessionInfo struct {
	SessionStart    time.Time `json:"session_start"`
	TotalOperations int64     `json:"total_operations"`
	UniqueKeys      int       `json:"unique_keys"`
	PeakMemoryUsage uint64    `json:"peak_memory_usage"`
	AverageLatency  float64   `json:"average_latency"`
	ErrorRate       float64   `json:"error_rate"`
}

func initializeMetricsCollector() {
	metricsCollector.mutex.Lock()
	defer metricsCollector.mutex.Unlock()

	if metricsCollector.initialized {
		return
	}

	metricsCollector.operationLatency = make(map[string][]time.Duration)
	metricsCollector.throughputMetrics = make(map[string]*throughputInfo)
	metricsCollector.errorCounts = make(map[string]int64)
	metricsCollector.sessionMetrics = &sessionInfo{
		SessionStart: time.Now(),
	}
	metricsCollector.initialized = true
}

func recordOperationLatency(operation string, duration time.Duration) {
	if !metricsCollector.initialized {
		initializeMetricsCollector()
	}

	metricsCollector.mutex.Lock()
	defer metricsCollector.mutex.Unlock()

	if _, exists := metricsCollector.operationLatency[operation]; !exists {
		metricsCollector.operationLatency[operation] = make([]time.Duration, 0, 1000)
	}

	metricsCollector.operationLatency[operation] = append(
		metricsCollector.operationLatency[operation],
		duration,
	)

	if len(metricsCollector.operationLatency[operation]) > 1000 {
		metricsCollector.operationLatency[operation] =
			metricsCollector.operationLatency[operation][len(metricsCollector.operationLatency[operation])-1000:]
	}

	metricsCollector.sessionMetrics.TotalOperations++
}

func recordThroughput(operation string, bytesCount int64) {
	if !metricsCollector.initialized {
		initializeMetricsCollector()
	}

	metricsCollector.mutex.Lock()
	defer metricsCollector.mutex.Unlock()

	now := time.Now()

	if throughput, exists := metricsCollector.throughputMetrics[operation]; exists {
		throughput.BytesProcessed += bytesCount
		throughput.OperationCount++
		throughput.LastUpdate = now
	} else {
		metricsCollector.throughputMetrics[operation] = &throughputInfo{
			BytesProcessed: bytesCount,
			OperationCount: 1,
			StartTime:      now,
			LastUpdate:     now,
		}
	}
}

func recordError(errorType string) {
	if !metricsCollector.initialized {
		initializeMetricsCollector()
	}

	metricsCollector.mutex.Lock()
	defer metricsCollector.mutex.Unlock()

	metricsCollector.errorCounts[errorType]++
}

func getLatencyStats(operation string) map[string]interface{} {
	if !metricsCollector.initialized {
		return map[string]interface{}{"initialized": false}
	}

	metricsCollector.mutex.RLock()
	defer metricsCollector.mutex.RUnlock()

	latencies, exists := metricsCollector.operationLatency[operation]
	if !exists || len(latencies) == 0 {
		return map[string]interface{}{"operation": operation, "samples": 0}
	}

	var total time.Duration
	min := latencies[0]
	max := latencies[0]

	for _, latency := range latencies {
		total += latency
		if latency < min {
			min = latency
		}
		if latency > max {
			max = latency
		}
	}

	avg := total / time.Duration(len(latencies))

	var p50, p95, p99 time.Duration
	if len(latencies) > 0 {
		sortedLatencies := make([]time.Duration, len(latencies))
		copy(sortedLatencies, latencies)

		n := len(sortedLatencies)
		for i := 0; i < n-1; i++ {
			for j := 0; j < n-i-1; j++ {
				if sortedLatencies[j] > sortedLatencies[j+1] {
					sortedLatencies[j], sortedLatencies[j+1] = sortedLatencies[j+1], sortedLatencies[j]
				}
			}
		}

		p50 = sortedLatencies[len(sortedLatencies)*50/100]
		p95 = sortedLatencies[len(sortedLatencies)*95/100]
		p99 = sortedLatencies[len(sortedLatencies)*99/100]
	}

	return map[string]interface{}{
		"operation":     operation,
		"samples":       len(latencies),
		"min_ns":        min.Nanoseconds(),
		"max_ns":        max.Nanoseconds(),
		"avg_ns":        avg.Nanoseconds(),
		"p50_ns":        p50.Nanoseconds(),
		"p95_ns":        p95.Nanoseconds(),
		"p99_ns":        p99.Nanoseconds(),
		"total_time_ns": total.Nanoseconds(),
	}
}

func getThroughputStats() map[string]interface{} {
	if !metricsCollector.initialized {
		return map[string]interface{}{"initialized": false}
	}

	metricsCollector.mutex.RLock()
	defer metricsCollector.mutex.RUnlock()

	stats := make(map[string]interface{})

	for operation, throughput := range metricsCollector.throughputMetrics {
		duration := throughput.LastUpdate.Sub(throughput.StartTime)
		if duration > 0 {
			bytesPerSecond := float64(throughput.BytesProcessed) / duration.Seconds()
			opsPerSecond := float64(throughput.OperationCount) / duration.Seconds()

			stats[operation] = map[string]interface{}{
				"bytes_processed":  throughput.BytesProcessed,
				"operation_count":  throughput.OperationCount,
				"duration_seconds": duration.Seconds(),
				"bytes_per_second": bytesPerSecond,
				"ops_per_second":   opsPerSecond,
				"start_time":       throughput.StartTime.Unix(),
				"last_update":      throughput.LastUpdate.Unix(),
			}
		}
	}

	return stats
}

func getSessionMetrics() map[string]interface{} {
	if !metricsCollector.initialized {
		return map[string]interface{}{"initialized": false}
	}

	metricsCollector.mutex.RLock()
	defer metricsCollector.mutex.RUnlock()

	session := metricsCollector.sessionMetrics
	uptime := time.Since(session.SessionStart)

	totalErrors := int64(0)
	for _, count := range metricsCollector.errorCounts {
		totalErrors += count
	}

	errorRate := float64(0)
	if session.TotalOperations > 0 {
		errorRate = float64(totalErrors) / float64(session.TotalOperations)
	}

	return map[string]interface{}{
		"session_start":    session.SessionStart.Unix(),
		"uptime_seconds":   uptime.Seconds(),
		"total_operations": session.TotalOperations,
		"total_errors":     totalErrors,
		"error_rate":       errorRate,
		"ops_per_second":   float64(session.TotalOperations) / uptime.Seconds(),
		"error_counts":     metricsCollector.errorCounts,
	}
}

func getAllMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	metrics["session"] = getSessionMetrics()
	metrics["throughput"] = getThroughputStats()
	metrics["errors"] = metricsCollector.errorCounts

	latencyStats := make(map[string]interface{})
	if metricsCollector.initialized {
		metricsCollector.mutex.RLock()
		for operation := range metricsCollector.operationLatency {
			latencyStats[operation] = getLatencyStats(operation)
		}
		metricsCollector.mutex.RUnlock()
	}
	metrics["latency"] = latencyStats

	return metrics
}

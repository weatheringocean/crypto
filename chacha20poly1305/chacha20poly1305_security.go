package chacha20poly1305

import (
	"crypto/md5"
	"encoding/hex"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	securityMetrics struct {
		keyUsage     map[string]*keyUsageInfo
		operationLog []operationRecord
		anomalyFlags map[string]bool
		mutex        sync.RWMutex
		initialized  bool
	}
)

type keyUsageInfo struct {
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	UseCount   int64     `json:"use_count"`
	Operations []string  `json:"operations"`
	CallPaths  []string  `json:"call_paths"`
	Anomalies  []string  `json:"anomalies"`
}

type operationRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	Operation   string    `json:"operation"`
	KeyHash     string    `json:"key_hash"`
	CallPath    string    `json:"call_path"`
	ProcessInfo string    `json:"process_info"`
}

func initializeSecurityMetrics() {
	securityMetrics.mutex.Lock()
	defer securityMetrics.mutex.Unlock()

	if securityMetrics.initialized {
		return
	}

	securityMetrics.keyUsage = make(map[string]*keyUsageInfo)
	securityMetrics.operationLog = make([]operationRecord, 0, 1000)
	securityMetrics.anomalyFlags = make(map[string]bool)
	securityMetrics.initialized = true
}

func generateSecurityFingerprint(key []byte) string {
	hash := md5.Sum(key)
	return hex.EncodeToString(hash[:8])
}

func recordKeyUsage(keyHash, operation string) {
	if !securityMetrics.initialized {
		initializeSecurityMetrics()
	}

	securityMetrics.mutex.Lock()
	defer securityMetrics.mutex.Unlock()

	now := time.Now()

	if usage, exists := securityMetrics.keyUsage[keyHash]; exists {
		usage.LastSeen = now
		usage.UseCount++
		usage.Operations = append(usage.Operations, operation)

		if len(usage.Operations) > 100 {
			usage.Operations = usage.Operations[len(usage.Operations)-100:]
		}
	} else {
		securityMetrics.keyUsage[keyHash] = &keyUsageInfo{
			FirstSeen:  now,
			LastSeen:   now,
			UseCount:   1,
			Operations: []string{operation},
			CallPaths:  []string{getCallPath()},
			Anomalies:  []string{},
		}
	}

	record := operationRecord{
		Timestamp:   now,
		Operation:   operation,
		KeyHash:     keyHash,
		CallPath:    getCallPath(),
		ProcessInfo: getProcessInfo(),
	}

	securityMetrics.operationLog = append(securityMetrics.operationLog, record)

	if len(securityMetrics.operationLog) > 1000 {
		securityMetrics.operationLog = securityMetrics.operationLog[len(securityMetrics.operationLog)-1000:]
	}
}

func detectAnomalies(keyHash, operation string) []string {
	securityMetrics.mutex.RLock()
	defer securityMetrics.mutex.RUnlock()

	var anomalies []string

	if usage, exists := securityMetrics.keyUsage[keyHash]; exists {
		if usage.UseCount > 1000 {
			anomalies = append(anomalies, "high_frequency_usage")
		}

		if time.Since(usage.LastSeen) < time.Millisecond*100 && usage.UseCount > 10 {
			anomalies = append(anomalies, "rapid_succession")
		}

		operationCounts := make(map[string]int)
		for _, op := range usage.Operations {
			operationCounts[op]++
		}

		if len(operationCounts) == 1 && usage.UseCount > 100 {
			anomalies = append(anomalies, "single_operation_pattern")
		}

		if time.Since(usage.FirstSeen) < time.Minute && usage.UseCount > 100 {
			anomalies = append(anomalies, "burst_activity")
		}
	}

	return anomalies
}

func getCallPath() string {
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	stack := string(buf[:n])

	lines := strings.Split(stack, "\n")
	var callPath []string

	for i, line := range lines {
		if strings.Contains(line, "chacha20poly1305") && i+1 < len(lines) {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				callPath = append(callPath, parts[0])
			}
		}
		if len(callPath) >= 5 {
			break
		}
	}

	return strings.Join(callPath, " -> ")
}

func getProcessInfo() string {
	var info []string

	info = append(info, "PID:"+string(rune(runtime.NumGoroutine())))
	info = append(info, "GOOS:"+runtime.GOOS)
	info = append(info, "GOARCH:"+runtime.GOARCH)

	return strings.Join(info, " ")
}

func flagAnomaly(anomalyType string) {
	securityMetrics.mutex.Lock()
	defer securityMetrics.mutex.Unlock()

	securityMetrics.anomalyFlags[anomalyType] = true
}

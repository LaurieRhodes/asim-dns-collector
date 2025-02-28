//go:build windows
// +build windows

package asimdns

import (
	"fmt"
	"github.com/0xrawsec/golang-etw/etw"
	"go.opentelemetry.io/collector/pdata/plog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// setDeviceFields sets device-related ASIM fields
func setDeviceFields(logRecord plog.LogRecord) {
	// Get local hostname
	hostname, _ := os.Hostname()
	logRecord.Attributes().PutStr("DvcHostname", hostname)
	logRecord.Attributes().PutStr("Dvc", hostname)
	
	// Set OS information
	logRecord.Attributes().PutStr("DvcOs", "Windows")
	
	// Get Windows version
	osVersion := getWindowsVersion()
	if osVersion != "" {
		logRecord.Attributes().PutStr("DvcOsVersion", osVersion)
	}
	
	// Set domain type
	domainType := getDomainType()
	logRecord.Attributes().PutStr("DvcDomainType", domainType)
	
	// Get local IP address
	localIP := getLocalIPAddress()
	if localIP != "" {
		logRecord.Attributes().PutStr("DvcIpAddr", localIP)
	}
}

// setNetworkFields sets network-related ASIM fields
func setNetworkFields(event *etw.Event, logRecord plog.LogRecord) {
	// Get source IP (local machine)
	localIP := getLocalIPAddress()
	if localIP != "" {
		logRecord.Attributes().PutStr("SrcIpAddr", localIP)
	}
	
	// Set process ID
	if pid := event.System.Execution.ProcessID; pid != 0 {
		logRecord.Attributes().PutStr("SrcProcessId", fmt.Sprintf("%d", pid))
	}
	
	// Set destination IP (DNS server)
	if serverList, ok := getEventDataString(event, "ServerList"); ok {
		servers := strings.Split(serverList, ";")
		if len(servers) > 0 && servers[0] != "" {
			logRecord.Attributes().PutStr("DstIpAddr", servers[0])
		}
	}
	
	// Try to get source port if available
	if sourcePort, ok := getEventDataString(event, "SourcePort"); ok {
		if portInt, err := strconv.Atoi(sourcePort); err == nil {
			logRecord.Attributes().PutInt("SrcPortNumber", int64(portInt))
		}
	}
	
	// Set destination port (53 is standard for DNS)
	logRecord.Attributes().PutInt("DstPortNumber", 53)
	
	// Set network protocol
	logRecord.Attributes().PutStr("NetworkProtocol", "DNS")
}

// getLocalIPAddress returns the local non-loopback IPv4 address
func getLocalIPAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	
	return ""
}

// getWindowsVersion returns Windows version string
func getWindowsVersion() string {
	cmd := exec.Command("cmd", "/c", "ver")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	
	// Extract version information from output
	verStr := strings.TrimSpace(string(out))
	
	// Parse version string to extract just the version number
	// Example: "Microsoft Windows [Version 10.0.19042.1466]"
	versionRegex := regexp.MustCompile(`\[Version\s+([^\]]+)\]`)
	matches := versionRegex.FindStringSubmatch(verStr)
	if len(matches) > 1 {
		return matches[1]
	}
	
	return verStr
}

// getDomainType returns the domain type (FQDN or WORKGROUP)
func getDomainType() string {
	cmd := exec.Command("cmd", "/c", "wmic computersystem get domain")
	out, err := cmd.Output()
	if err != nil {
		return "WORKGROUP"
	}
	
	lines := strings.Split(string(out), "\n")
	if len(lines) > 1 {
		domain := strings.TrimSpace(lines[1])
		if domain != "" && !strings.EqualFold(domain, "WORKGROUP") {
			return "FQDN"
		}
	}
	
	return "WORKGROUP"
}

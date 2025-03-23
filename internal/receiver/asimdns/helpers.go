package asimdns

import (
	"github.com/0xrawsec/golang-etw/etw"
	"go.opentelemetry.io/collector/pdata/plog"
	"net"
	"os"
	"strconv"
)

// setDeviceFields adds device-related information to the ASIM log record
func setDeviceFields(logRecord plog.LogRecord) {
	// Get local hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}
	
	// Get local IP
	localIP := getLocalIP()
	
	// Set device fields
	logRecord.Attributes().PutStr("DvcHostname", hostname)
	logRecord.Attributes().PutStr("DvcId", hostname)
	logRecord.Attributes().PutStr("DvcScopeId", hostname)
	logRecord.Attributes().PutStr("Dvc", hostname) // Required by ADX function
	logRecord.Attributes().PutStr("DvcIpAddr", localIP) // Required by ADX function
	
	// Set OS info
	logRecord.Attributes().PutStr("DvcOs", "Windows")
	logRecord.Attributes().PutStr("DvcOsVersion", "Windows Server")
	logRecord.Attributes().PutStr("DvcDomainType", "Windows") // Required by ADX schema
}

// setNetworkFields extracts network information from the DNS Client event
func setNetworkFields(event *etw.Event, logRecord plog.LogRecord) {
	// Extract server list (for DNS Client events)
	if serverList, ok := getEventDataString(event, "ServerList"); ok {
		logRecord.Attributes().PutStr("DstIpAddr", serverList)
	}
	
	// Extract source port if available
	if sourcePort, ok := getEventDataString(event, "SourcePort"); ok {
		if portInt, err := strconv.Atoi(sourcePort); err == nil {
			logRecord.Attributes().PutInt("SrcPortNumber", int64(portInt))
		}
	}
	
	// Set destination port for DNS (typically 53)
	logRecord.Attributes().PutInt("DstPortNumber", 53)
	
	// Default to UDP for DNS
	logRecord.Attributes().PutStr("NetworkProtocol", "UDP")
	
	// Set process ID field that's required by ADX schema
	logRecord.Attributes().PutStr("SrcProcessId", strconv.Itoa(int(event.System.Execution.ProcessID)))
}

// getLocalIP returns the non-loopback IP address of the host
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	
	for _, address := range addrs {
		// Check the address type and if it's not a loopback
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

//go:build windows
// +build windows

package asimdns

import (
	"fmt"
	"github.com/0xrawsec/golang-etw/etw"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"strconv"
	"time"
)

// getAsimDnsServerEventType determines ASIM event type and subtype based on DNS Server ETW event ID
func getAsimDnsServerEventType(eventID uint16) (string, string) {
	// DNS Server event IDs have different semantics than DNS Client
	// Map to ASIM schema types
	switch eventID {
	// These are the main event IDs from the DNS Server provider
	case 256, 257: // Query received events
		return "Query", "request"
	case 258, 259: // Response events
		return "Query", "response"
	case 260, 261: // Recursion events
		return "Query", "recursive"
	default:
		return "Info", "status"
	}
}

// handleDnsServerEvent processes events from the DNS Server provider
// and ensures they are correctly mapped to ASIM schema
func handleDnsServerEvent(event *etw.Event, logRecord plog.LogRecord) {
	// Set proper timestamps using the Unix nano format expected by ADX
	eventTime := event.System.TimeCreated.SystemTime
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(eventTime))
	logRecord.SetObservedTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	
	// Set DNS Server specific resource attributes
	logRecord.Attributes().PutStr("EventProduct", "DNS Server")
	logRecord.Attributes().PutStr("EventVendor", "Microsoft")
	logRecord.Attributes().PutStr("EventOriginalType", strconv.Itoa(int(event.System.EventID)))
	
	// Set common ASIM fields
	logRecord.Attributes().PutInt("EventCount", 1)
	
	// Set DNS session ID for correlation
	sessionID := fmt.Sprintf("%d-%d-%d", 
		event.System.Execution.ProcessID, 
		event.System.EventID, 
		event.System.TimeCreated.SystemTime.UnixNano())
	logRecord.Attributes().PutStr("DnsSessionId", sessionID)
	
	// Set process information
	logRecord.Attributes().PutStr("SrcProcessId", strconv.Itoa(int(event.System.Execution.ProcessID)))
	
	// Set device information fields
	setDeviceFields(logRecord)
	
	// Determine event type and subtype based on DNS Server event ID
	eventType, eventSubType := getAsimDnsServerEventType(event.System.EventID)
	logRecord.Attributes().PutStr("EventType", eventType)
	logRecord.Attributes().PutStr("EventSubType", eventSubType)
	
	// Set standard query information if available
	if queryName, ok := getEventDataString(event, "QNAME"); ok {
		logRecord.Attributes().PutStr("DnsQuery", queryName)
	}
	
	// Handle DNS Server specific flags and record types
	if queryType, ok := getEventDataString(event, "QTYPE"); ok {
		if queryTypeInt, err := strconv.Atoi(queryType); err == nil {
			logRecord.Attributes().PutInt("DnsQueryType", int64(queryTypeInt))
			logRecord.Attributes().PutStr("DnsQueryTypeName", getDnsQueryTypeName(queryTypeInt))
		}
	}
	
	// Extract client IP - try multiple field names that may contain source IP
	srcIP := ""
	for _, field := range []string{"CLIENT_IP", "Source", "InterfaceIP"} {
		if value, ok := getEventDataString(event, field); ok && value != "" {
			srcIP = value
			break
		}
	}
	if srcIP != "" {
		logRecord.Attributes().PutStr("SrcIpAddr", srcIP)
	}
	
	// Extract server IP - try multiple field names that may contain destination IP
	dstIP := ""
	for _, field := range []string{"SERVER_IP", "Destination"} {
		if value, ok := getEventDataString(event, field); ok && value != "" {
			dstIP = value
			break
		}
	}
	if dstIP != "" {
		logRecord.Attributes().PutStr("DstIpAddr", dstIP)
	}
	
	// Extract port information if available
	if port, ok := getEventDataString(event, "Port"); ok {
		if portInt, err := strconv.Atoi(port); err == nil {
			logRecord.Attributes().PutInt("SrcPortNumber", int64(portInt))
		}
	}
	
	// Set destination port - always 53 for DNS
	logRecord.Attributes().PutInt("DstPortNumber", 53)
	
	// Set network protocol (UDP/TCP)
	if tcp, ok := getEventDataString(event, "TCP"); ok {
		protocol := "UDP"
		if tcp == "1" {
			protocol = "TCP"
		}
		logRecord.Attributes().PutStr("NetworkProtocol", protocol)
	} else {
		// Default to UDP if not specified
		logRecord.Attributes().PutStr("NetworkProtocol", "UDP")
	}
	
	// Process DNS flags
	dnsFlags := []string{}
	
	// RD (Recursion Desired) flag
	rdFlag := false
	if rd, ok := getEventDataString(event, "RD"); ok && rd == "1" {
		rdFlag = true
		dnsFlags = append(dnsFlags, "RD")
	}
	logRecord.Attributes().PutBool("DnsFlagsRecursionDesired", rdFlag)
	
	// CD (Checking Disabled) flag - required by schema
	cdFlag := false
	if cd, ok := getEventDataString(event, "CD"); ok && cd == "1" {
		cdFlag = true
		dnsFlags = append(dnsFlags, "CD")
	}
	logRecord.Attributes().PutBool("DnsFlagsCheckingDisabled", cdFlag)
	
	// AA (Authoritative Answer) flag
	if aa, ok := getEventDataString(event, "AA"); ok && aa == "1" {
		dnsFlags = append(dnsFlags, "AA")
	}
	
	// AD (Authenticated Data) flag
	if ad, ok := getEventDataString(event, "AD"); ok && ad == "1" {
		dnsFlags = append(dnsFlags, "AD")
	}
	
	// Set combined flags string
	if len(dnsFlags) > 0 {
		logRecord.Attributes().PutStr("DnsFlags", fmt.Sprintf("%v", dnsFlags))
	} else {
		// Ensure the field exists even if empty
		logRecord.Attributes().PutStr("DnsFlags", "")
	}
	
	// Process response code for response events
	if eventSubType == "response" {
		if rcode, ok := getEventDataString(event, "RCODE"); ok {
			if rcodeInt, err := strconv.Atoi(rcode); err == nil {
				logRecord.Attributes().PutInt("DnsResponseCode", int64(rcodeInt))
				responseName := getDnsResponseName(rcodeInt)
				logRecord.Attributes().PutStr("DnsResponseName", responseName)
				
				// Set EventResult based on response code
				if rcodeInt == 0 {
					logRecord.Attributes().PutStr("EventResult", "Success")
				} else {
					logRecord.Attributes().PutStr("EventResult", "Failure")
				}
				logRecord.Attributes().PutStr("EventResultDetails", responseName)
			}
		}
	} else {
		// For non-response events
		logRecord.Attributes().PutStr("EventResult", "NA")
		logRecord.Attributes().PutStr("EventResultDetails", "NA")
	}

	// Additional DNS Server specific fields
	if zone, ok := getEventDataString(event, "Zone"); ok {
		logRecord.Attributes().PutStr("DnsZone", zone)
	}
	
	// Add all other fields as additional fields
	setAdditionalFields(event, logRecord)
}

// isDnsServerEvent checks if an event is from the DNS Server provider
func isDnsServerEvent(event *etw.Event) bool {
	return event.System.Provider.Guid == DNSServerProviderGUID
}

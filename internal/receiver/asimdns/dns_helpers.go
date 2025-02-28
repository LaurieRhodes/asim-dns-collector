//go:build windows
// +build windows

package asimdns

import (
	"encoding/json"
	"fmt"
	"github.com/0xrawsec/golang-etw/etw"
	"go.opentelemetry.io/collector/pdata/plog"
	"strconv"
)

// setResponseFields sets fields specific to DNS response events
func setResponseFields(event *etw.Event, logRecord plog.LogRecord) {
	// Extract status code
	if status, ok := getEventDataString(event, "Status"); ok {
		if statusInt, err := strconv.Atoi(status); err == nil {
			// Set response code
			logRecord.Attributes().PutInt("DnsResponseCode", int64(statusInt))
			
			// Set response name
			responseName := getDnsResponseName(statusInt)
			logRecord.Attributes().PutStr("DnsResponseName", responseName)
			
			// Set event result based on status
			if statusInt == 0 {
				logRecord.Attributes().PutStr("EventResult", "Success")
			} else {
				logRecord.Attributes().PutStr("EventResult", "Failure")
			}
			
			// Set result details to the response name
			logRecord.Attributes().PutStr("EventResultDetails", responseName)
		}
	} else if status, ok := getEventDataString(event, "QueryStatus"); ok {
		// Alternative field name for status
		if statusInt, err := strconv.Atoi(status); err == nil {
			// Set response code
			logRecord.Attributes().PutInt("DnsResponseCode", int64(statusInt))
			
			// Set response name
			responseName := getDnsResponseName(statusInt)
			logRecord.Attributes().PutStr("DnsResponseName", responseName)
			
			// Set event result based on status
			if statusInt == 0 {
				logRecord.Attributes().PutStr("EventResult", "Success")
			} else {
				logRecord.Attributes().PutStr("EventResult", "Failure")
			}
			
			// Set result details to the response name
			logRecord.Attributes().PutStr("EventResultDetails", responseName)
		}
	} else {
		// Default values if status is not available
		logRecord.Attributes().PutStr("EventResult", "Unknown")
		logRecord.Attributes().PutStr("EventResultDetails", "NoStatusCode")
	}
	
	// Add query duration if available
	if duration, ok := getEventDataString(event, "QueryDuration"); ok {
		if durationInt, err := strconv.Atoi(duration); err == nil {
			logRecord.Attributes().PutInt("DnsNetworkDuration", int64(durationInt))
		}
	}
}

// setDnsFlags adds DNS flags to the log record attributes
func setDnsFlags(flags uint64, logRecord plog.LogRecord) {
	// Extract individual flags based on DNS standard flags
	recursionDesired := (flags & 0x100) != 0
	checkingDisabled := (flags & 0x10) != 0
	
	// Set individual flag fields
	logRecord.Attributes().PutBool("DnsFlagsRecursionDesired", recursionDesired)
	logRecord.Attributes().PutBool("DnsFlagsCheckingDisabled", checkingDisabled)
	
	// Build flags string representation
	var flagsStr string
	if recursionDesired && checkingDisabled {
		flagsStr = "RD CD"
	} else if recursionDesired {
		flagsStr = "RD"
	} else if checkingDisabled {
		flagsStr = "CD"
	} else {
		flagsStr = ""
	}
	
	// Set the combined flags string
	logRecord.Attributes().PutStr("DnsFlags", flagsStr)
}

// setAdditionalFields adds any remaining ETW fields as a JSON object in AdditionalFields
func setAdditionalFields(event *etw.Event, logRecord plog.LogRecord) {
	additionalFields := extractAdditionalFields(event)
	if len(additionalFields) > 0 {
		additionalJSON, _ := json.Marshal(additionalFields)
		logRecord.Attributes().PutStr("AdditionalFields", string(additionalJSON))
	} else {
		// Add empty JSON object for consistency
		logRecord.Attributes().PutStr("AdditionalFields", "{}")
	}
}

// getAsimEventType determines ASIM event type and subtype based on ETW event ID
func getAsimEventType(eventID uint16) (string, string) {
	switch eventID {
	case 3006:
		return "Query", "request"
	case 3008:
		return "Query", "response"
	case 3020:
		return "DnsCache", "add"
	case 3019:
		return "DnsCache", "remove"
	default:
		return "Info", "status"
	}
}

// getDnsQueryTypeName maps DNS query type number to name
func getDnsQueryTypeName(queryType int) string {
	switch queryType {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE%d", queryType)
	}
}

// getDnsResponseName maps DNS response code to name
func getDnsResponseName(responseCode int) string {
	switch responseCode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	case 6:
		return "YXDOMAIN"
	case 7:
		return "YXRRSET"
	case 8:
		return "NXRRSET"
	case 9:
		return "NOTAUTH"
	case 10:
		return "NOTZONE"
	default:
		return fmt.Sprintf("RCODE%d", responseCode)
	}
}

// getEventDataString safely extracts a string value from event data
func getEventDataString(event *etw.Event, key string) (string, bool) {
	if value, ok := event.EventData[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue, true
		}
	}
	return "", false
}

// extractAdditionalFields collects non-standard fields from the event
func extractAdditionalFields(event *etw.Event) map[string]interface{} {
	additionalFields := make(map[string]interface{})
	
	// Standard ASIM fields that are already mapped
	standardFields := map[string]bool{
		"QueryName":     true,
		"QueryType":     true,
		"Status":        true,
		"QueryStatus":   true,
		"ServerList":    true,
		"SourcePort":    true,
		"QueryOptions":  true,
		"QueryDuration": true,
	}
	
	// Add any fields not already mapped to standard ASIM fields
	for key, value := range event.EventData {
		if !standardFields[key] {
			additionalFields[key] = value
		}
	}
	
	return additionalFields
}

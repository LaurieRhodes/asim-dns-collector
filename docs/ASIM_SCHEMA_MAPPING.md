# ASIM DNS Schema Mapping Guide

## Overview

This document provides detailed guidance for transforming Windows DNS Server ETW events into the Microsoft Sentinel ASIM DNS Activity Logs schema. The ASIM (Advanced Security Information Model) provides a normalized schema across different data sources, enabling consistent analytics and threat detection.

## ASIM DNS Activity Logs Schema

The ASIM DNS Activity Logs schema is a comprehensive schema for representing DNS-related events. The full schema definition includes numerous fields covering various aspects of DNS operations:

```
.create-merge table ASimDnsActivityLogs (
    TenantId: string,
    TimeGenerated: datetime,
    EventCount: int,
    EventType: string,
    EventSubType: string,
    EventResult: string,
    EventResultDetails: string,
    EventOriginalType: string,
    EventProduct: string,
    EventVendor: string,
    DvcIpAddr: string,
    DvcHostname: string,
    DvcDomain: string,
    DvcDomainType: string,
    DvcOs: string,
    DvcOsVersion: string,
    AdditionalFields: dynamic,
    SrcIpAddr: string,
    SrcPortNumber: int,
    SrcGeoCountry: string,
    SrcGeoRegion: string,
    SrcGeoCity: string,
    SrcGeoLatitude: real,
    SrcGeoLongitude: real,
    DstIpAddr: string,
    DstGeoCountry: string,
    DstGeoRegion: string,
    DstGeoCity: string,
    DstGeoLatitude: real,
    DstGeoLongitude: real,
    DnsQuery: string,
    DnsQueryType: int,
    DnsQueryTypeName: string,
    DnsResponseCode: int,
    DnsResponseName: string,
    TransactionIdHex: string,
    DstDescription: string,
    DstDvcScope: string,
    DstOriginalRiskLevel: string,
    DstRiskLevel: int,
    DvcDescription: string,
    DvcInterface: string,
    DvcOriginalAction: string,
    DvcScope: string,
    DvcScopeId: string,
    EventOriginalSeverity: string,
    NetworkProtocolVersion: string,
    RuleName: string,
    RuleNumber: int,
    DnsResponseIpCountry: string,
    DnsResponseIpLatitude: real,
    DnsResponseIpLongitude: real,
    NetworkProtocol: string,
    DnsQueryClass: int,
    DnsQueryClassName: string,
    DnsNetworkDuration: int,
    DnsFlagsAuthenticated: bool,
    DnsFlagsAuthoritative: bool,
    DnsFlagsRecursionDesired: bool,
    DnsSessionId: string,
    SrcDescription: string,
    SrcDvcScope: string,
    SrcDvcScopeId: string,
    SrcOriginalRiskLevel: string,
    SrcUserScope: string,
    SrcUserScopeId: string,
    SrcUserSessionId: string,
    ThreatId: string,
    ThreatIpAddr: string,
    ThreatField: string,
    UrlCategory: string,
    ThreatCategory: string,
    ThreatName: string,
    ThreatConfidence: int,
    ThreatOriginalConfidence: string,
    ThreatRiskLevel: int,
    ThreatOriginalRiskLevel_s: string,
    ThreatOriginalRiskLevel: int,
    ThreatIsActive: bool,
    ThreatFirstReportedTime: string,
    ThreatFirstReportedTime_d: datetime,
    ThreatLastReportedTime: string,
    ThreatLastReportedTime_d: datetime,
    EventStartTime: datetime,
    EventEndTime: datetime,
    EventMessage: string,
    EventOriginalUid: string,
    EventReportUrl: string,
    EventSchemaVersion: string,
    Dvc: string,
    DvcFQDN: string,
    DvcId: string,
    DvcIdType: string,
    DvcMacAddr: string,
    DvcZone: string,
    DnsResponseIpCity: string,
    DnsResponseIpRegion: string,
    EventOwner: string,
    EventProductVersion: string,
    EventSeverity: string,
    Src: string,
    SrcHostname: string,
    SrcDomain: string,
    SrcDomainType: string,
    SrcFQDN: string,
    SrcDvcId: string,
    SrcDvcIdType: string,
    SrcDeviceType: string,
    SrcRiskLevel: int,
    SrcUserId: string,
    SrcUserIdType: string,
    SrcUsername: string,
    SrcUsernameType: string,
    SrcUserType: string,
    SrcOriginalUserType: string,
    SrcProcessName: string,
    SrcProcessId: string,
    SrcProcessGuid: string,
    Dst: string,
    DstPortNumber: int,
    DstHostname: string,
    DstDomain: string,
    DstDomainType: string,
    DstFQDN: string,
    DstDvcId: string,
    DstDvcScopeId: string,
    DstDvcIdType: string,
    DstDeviceType: string,
    DvcAction: string,
    DnsFlags: string,
    DnsFlagsCheckingDisabled: bool,
    DnsFlagsRecursionAvailable: bool,
    DnsFlagsTruncated: bool,
    DnsFlagsZ: bool,
    SourceSystem: string,
    Type: string,
    _ResourceId: string
)
```

## Windows DNS Server ETW Events to ASIM Mapping

The mapping from Windows DNS Server ETW events to ASIM DNS Activity Logs requires identifying event types, extracting relevant fields, and transforming them into the ASIM schema.

### Key Event Types

1. **Query Received Events (Event ID 256, 257)**
   - Represents DNS queries being received by the server
   - Event type: "Query"
   - Event subtype: "request"

2. **Response Events (Event ID 258, 259)**
   - Represents DNS responses sent by the server
   - Event type: "Query"
   - Event subtype: "response"

3. **Recursion Events (Event ID 260, 261)**
   - Represents DNS recursion operations
   - Event type: "Query"
   - Event subtype: "recursive"

### Core Field Mapping

| ASIM Field | Data Type | ETW Source | Transformation Logic |
|------------|-----------|------------|----------------------|
| TimeGenerated | datetime | event timestamp | Direct mapping |
| EventCount | int | N/A | Default to 1 |
| EventType | string | event.id | "Query" for 256/257/258/259, "Query" for 260/261 |
| EventSubType | string | event.id | "request" for 256/257, "response" for 258/259, "recursive" for 260/261 |
| EventResult | string | dns.RCODE | "Success" for successful responses (RCODE=0), "Failure" otherwise |
| EventResultDetails | string | dns.RCODE | Map DNS response codes to names |
| EventOriginalType | string | event.id | Direct mapping |
| EventProduct | string | N/A | "DNS Server" |
| EventVendor | string | N/A | "Microsoft" |
| DvcIpAddr | string | Context | Local IP (may need OS API) |
| DvcHostname | string | Context | Local hostname (may need OS API) |
| DvcDomainType | string | Context | "FQDN" |
| DvcOs | string | Context | "Windows" |
| SrcIpAddr | string | dns.CLIENT_IP / dns.Source | Client IP address |
| SrcPortNumber | int | dns.Port | Client port |
| DstIpAddr | string | dns.SERVER_IP / dns.Destination | Server IP |
| DnsQuery | string | dns.QNAME | Direct mapping |
| DnsQueryType | int | dns.QTYPE | Direct mapping (e.g., 1 for A, 28 for AAAA) |
| DnsQueryTypeName | string | dns.QTYPE | Map type codes (1="A", 28="AAAA", etc.) |
| DnsResponseCode | int | dns.RCODE | Direct mapping |
| DnsResponseName | string | dns.RCODE | Map response codes (0="NOERROR", 3="NXDOMAIN", etc.) |
| NetworkProtocol | string | dns.TCP | "TCP" if TCP=1, otherwise "UDP" |
| DnsFlagsRecursionDesired | bool | dns.RD | True if RD=1 |
| DnsFlagsCheckingDisabled | bool | dns.CD | True if CD=1 |
| DnsFlags | string | Derived | Combination of flags (RD, CD, AA, AD) |
| DnsZone | string | dns.Zone | Direct mapping if available |

### ETW Event Sample

Current ETW event capture format from our collector for a DNS Server query event:

```json
{
  "scopeLogs": [
    {
      "scope": {
        "name": "asim.dns.events"
      },
      "logRecords": [
        {
          "timeUnixNano": "1740474551984079100",
          "body": {
            "stringValue": "DNS Server Event: Query request (ID: 256)"
          },
          "attributes": [
            {
              "key": "EventType",
              "value": {
                "stringValue": "Query"
              }
            },
            {
              "key": "EventSubType",
              "value": {
                "stringValue": "request"
              }
            },
            {
              "key": "EventProduct",
              "value": {
                "stringValue": "DNS Server"
              }
            },
            {
              "key": "EventVendor",
              "value": {
                "stringValue": "Microsoft"
              }
            },
            {
              "key": "EventOriginalType",
              "value": {
                "stringValue": "256"
              }
            },
            {
              "key": "EventCount",
              "value": {
                "intValue": "1"
              }
            },
            {
              "key": "SrcIpAddr",
              "value": {
                "stringValue": "10.0.0.15"
              }
            },
            {
              "key": "SrcPortNumber",
              "value": {
                "intValue": "50432"
              }
            },
            {
              "key": "DstPortNumber",
              "value": {
                "intValue": "53"
              }
            },
            {
              "key": "NetworkProtocol",
              "value": {
                "stringValue": "UDP"
              }
            },
            {
              "key": "DnsQuery",
              "value": {
                "stringValue": "www.example.com"
              }
            },
            {
              "key": "DnsQueryType",
              "value": {
                "intValue": "1"
              }
            },
            {
              "key": "DnsQueryTypeName",
              "value": {
                "stringValue": "A"
              }
            },
            {
              "key": "DnsFlagsRecursionDesired",
              "value": {
                "boolValue": true
              }
            },
            {
              "key": "DnsFlagsCheckingDisabled",
              "value": {
                "boolValue": false
              }
            },
            {
              "key": "DnsFlags",
              "value": {
                "stringValue": "RD"
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### ASIM Target Format Example

Expected ASIM DNS Activity Logs format:

```csv
"TimeGenerated [UTC]",EventCount,EventType,EventSubType,EventResult,EventResultDetails,EventOriginalType,EventProduct,EventVendor,DvcIpAddr,DvcHostname,DvcDomainType,DvcOs,DvcOsVersion,AdditionalFields,SrcIpAddr,SrcPortNumber,DstIpAddr,DnsQuery,DnsQueryType
"2/25/2025, 9:19:25.391 AM",1,Query,request,NA,NA,256,"DNS Server",Microsoft,"10.5.0.7",DNS,FQDN,Windows,"10.0.14393.0","{}","10.0.0.15",50432,"10.5.0.7","www.example.com",1
```

## Implementation Strategy

The transformation from ETW events to ASIM schema is implemented in the `handleDnsServerEvent` function within the `dns_server_helpers.go` file. The implementation:

1. Determines the event type based on the ETW event ID
2. Extracts relevant fields from the ETW event
3. Maps ETW fields to ASIM schema fields
4. Sets default values for required fields when source data is unavailable
5. Formats the output according to ASIM schema requirements

### Pseudo Code

```go
func handleDnsServerEvent(event *etw.Event, logRecord plog.LogRecord) {
    // Set proper timestamps
    eventTime := event.System.TimeCreated.SystemTime
    logRecord.SetTimestamp(pcommon.NewTimestampFromTime(eventTime))
    logRecord.SetObservedTimestamp(pcommon.NewTimestampFromTime(time.Now()))
    
    // Set DNS Server specific resource attributes
    logRecord.Attributes().PutStr("EventProduct", "DNS Server")
    logRecord.Attributes().PutStr("EventVendor", "Microsoft")
    logRecord.Attributes().PutStr("EventOriginalType", strconv.Itoa(int(event.System.EventID)))
    
    // Set common ASIM fields
    logRecord.Attributes().PutInt("EventCount", 1)
    
    // Determine event type and subtype based on DNS Server event ID
    eventType, eventSubType := getAsimDnsServerEventType(event.System.EventID)
    logRecord.Attributes().PutStr("EventType", eventType)
    logRecord.Attributes().PutStr("EventSubType", eventSubType)
    
    // Set standard query information if available
    if queryName, ok := getEventDataString(event, "QNAME"); ok {
        logRecord.Attributes().PutStr("DnsQuery", queryName)
    }
    
    // Handle DNS Server specific fields
    if queryType, ok := getEventDataString(event, "QTYPE"); ok {
        if queryTypeInt, err := strconv.Atoi(queryType); err == nil {
            logRecord.Attributes().PutInt("DnsQueryType", int64(queryTypeInt))
            logRecord.Attributes().PutStr("DnsQueryTypeName", getDnsQueryTypeName(queryTypeInt))
        }
    }
    
    // Extract client IP
    if srcIP, ok := getEventDataString(event, "CLIENT_IP"); ok {
        logRecord.Attributes().PutStr("SrcIpAddr", srcIP)
    }
    
    // Extract client port
    if port, ok := getEventDataString(event, "Port"); ok {
        if portInt, err := strconv.Atoi(port); err == nil {
            logRecord.Attributes().PutInt("SrcPortNumber", int64(portInt))
        }
    }
    
    // Set destination port - always 53 for DNS
    logRecord.Attributes().PutInt("DstPortNumber", 53)
    
    // Process DNS flags
    if rd, ok := getEventDataString(event, "RD"); ok && rd == "1" {
        logRecord.Attributes().PutBool("DnsFlagsRecursionDesired", true)
    }
    
    // Process response code for response events
    if eventSubType == "response" {
        if rcode, ok := getEventDataString(event, "RCODE"); ok {
            if rcodeInt, err := strconv.Atoi(rcode); err == nil {
                logRecord.Attributes().PutInt("DnsResponseCode", int64(rcodeInt))
                logRecord.Attributes().PutStr("DnsResponseName", getDnsResponseName(rcodeInt))
                
                // Set EventResult based on response code
                if rcodeInt == 0 {
                    logRecord.Attributes().PutStr("EventResult", "Success")
                } else {
                    logRecord.Attributes().PutStr("EventResult", "Failure")
                }
            }
        }
    }
}

// Maps DNS Server event IDs to ASIM event types
func getAsimDnsServerEventType(eventID uint16) (string, string) {
    switch eventID {
    case 256, 257:
        return "Query", "request"
    case 258, 259:
        return "Query", "response"
    case 260, 261:
        return "Query", "recursive"
    default:
        return "Info", "status"
    }
}
```

## DNS Query Type Mapping

DNS Query Types are mapped to their corresponding names:

| QueryType | QueryTypeName |
|-----------|---------------|
| 1 | A |
| 2 | NS |
| 5 | CNAME |
| 6 | SOA |
| 12 | PTR |
| 15 | MX |
| 16 | TXT |
| 28 | AAAA |
| 33 | SRV |
| 65 | HTTPS |

## DNS Response Code Mapping

DNS Response Codes are mapped to their corresponding names:

| ResponseCode | ResponseName |
|--------------|--------------|
| 0 | NOERROR |
| 1 | FORMERR |
| 2 | SERVFAIL |
| 3 | NXDOMAIN |
| 4 | NOTIMP |
| 5 | REFUSED |
| 6 | YXDOMAIN |
| 7 | YXRRSET |
| 8 | NXRRSET |
| 9 | NOTAUTH |
| 10 | NOTZONE |

## Testing and Validation

To ensure correct transformation:

1. Compare the transformed output with expected ASIM format
2. Validate required fields are properly populated
3. Verify field mappings for different event types
4. Test with various DNS query types and response codes
5. Handle edge cases like missing fields or unusual values

## Next Steps

1. Implement any missing field mappings for ASIM compatibility
2. Develop unit tests for the transformation
3. Add validation to ensure ASIM compatibility
4. Document any limitations or assumptions in the mapping

## References

- [Microsoft Sentinel ASIM DNS Normalization Schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-dns)
- [Windows DNS Server ETW Provider GUID](https://learn.microsoft.com/en-us/windows/win32/etw/microsoft-windows-dnsserver)
- [DNS Protocol RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)

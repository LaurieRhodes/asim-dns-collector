# ASIM DNS Schema Mapping Guide

## Overview

This document provides detailed guidance for transforming Windows DNS Client ETW events into the Microsoft Sentinel ASIM DNS Activity Logs schema. The ASIM (Advanced Security Information Model) provides a normalized schema across different data sources, enabling consistent analytics and threat detection.

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

## Windows DNS Client ETW Events to ASIM Mapping

The mapping from Windows DNS Client ETW events to ASIM DNS Activity Logs requires identifying event types, extracting relevant fields, and transforming them into the ASIM schema.

### Key Event Types

1. **Query Events (Event ID 3006)**
   - Represents DNS queries being sent
   - Event type: "Query"
   - Event subtype: "request"

2. **Response Events (Event ID 3008)**
   - Represents DNS responses received
   - Event type: "Query"
   - Event subtype: "response"

3. **Cache Events (Event IDs 3019, 3020)**
   - Represents DNS cache operations
   - Event type: "DnsCache"
   - Event subtype based on operation (add/remove)

### Core Field Mapping

| ASIM Field | Data Type | ETW Source | Transformation Logic |
|------------|-----------|------------|----------------------|
| TimeGenerated | datetime | event timestamp | Direct mapping |
| EventCount | int | N/A | Default to 1 |
| EventType | string | event.id | "Query" for 3006/3008, "DnsCache" for 3019/3020 |
| EventSubType | string | event.id | "request" for 3006, "response" for 3008 |
| EventResult | string | dns.Status | "Success" for successful responses, "Failure" otherwise |
| EventResultDetails | string | dns.Status | Map DNS status codes to names |
| EventOriginalType | string | event.id | Direct mapping |
| EventProduct | string | N/A | "DNS Client" |
| EventVendor | string | N/A | "Microsoft" |
| DvcIpAddr | string | Context | Local IP (may need OS API) |
| DvcHostname | string | Context | Local hostname (may need OS API) |
| DvcDomainType | string | Context | "FQDN" |
| DvcOs | string | Context | "Windows" |
| SrcIpAddr | string | Context | Local IP for queries, DNS server IP for responses |
| SrcPortNumber | int | dns context | Local port for queries |
| DstIpAddr | string | dns.ServerList | DNS server IP |
| DnsQuery | string | dns.QueryName | Direct mapping |
| DnsQueryType | int | dns.QueryType | Direct mapping (e.g., 1 for A, 28 for AAAA) |
| DnsQueryTypeName | string | dns.QueryType | Map type codes (1="A", 28="AAAA", etc.) |

### ETW Event Sample

Current ETW event capture format from our collector:

```json
{
  "scopeLogs": [
    {
      "scope": {
        "name": "dns.client.events"
      },
      "logRecords": [
        {
          "timeUnixNano": "1740474551984079100",
          "body": {
            "stringValue": "DNS Event: 3006"
          },
          "attributes": [
            {
              "key": "provider.name",
              "value": {
                "stringValue": "Microsoft-Windows-DNS-Client"
              }
            },
            {
              "key": "provider.guid",
              "value": {
                "stringValue": "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
              }
            },
            {
              "key": "event.id",
              "value": {
                "intValue": "3006"
              }
            },
            {
              "key": "process.pid",
              "value": {
                "intValue": "5988"
              }
            },
            {
              "key": "thread.id",
              "value": {
                "intValue": "5060"
              }
            },
            {
              "key": "dns.QueryType",
              "value": {
                "stringValue": "28"
              }
            },
            {
              "key": "dns.QueryOptions",
              "value": {
                "stringValue": "213000"
              }
            },
            {
              "key": "dns.ServerList",
              "value": {
                "stringValue": "127.0.0.1;"
              }
            },
            {
              "key": "dns.IsNetworkQuery",
              "value": {
                "stringValue": "0"
              }
            },
            {
              "key": "dns.NetworkQueryIndex",
              "value": {
                "stringValue": "0"
              }
            },
            {
              "key": "dns.InterfaceIndex",
              "value": {
                "stringValue": "0"
              }
            },
            {
              "key": "dns.IsAsyncQuery",
              "value": {
                "stringValue": "0"
              }
            },
            {
              "key": "dns.QueryName",
              "value": {
                "stringValue": "www.github.com"
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
"2/25/2025, 9:19:25.391 AM",1,Query,request,NA,NA,256,"DNS Server",Microsoft,"10.5.0.7",DNS,FQDN,Windows,"10.0.14393.0","{}","10.5.0.7",63874,"10.5.0.7","www.microsoft.com",1
```

## Implementation Strategy

The transformation from ETW events to ASIM schema should be implemented in the `convertEventToLogs` function within the `asimdns_windows.go` file. The implementation should:

1. Determine the event type based on the ETW event ID
2. Extract relevant fields from the ETW event
3. Map ETW fields to ASIM schema fields
4. Set default values for required fields when source data is unavailable
5. Format the output according to ASIM schema requirements

### Pseudo Code

```go
func convertEventToLogs(event *etw.Event) plog.Logs {
    logs := plog.NewLogs()
    resourceLogs := logs.ResourceLogs().AppendEmpty()
    
    // Set resource attributes
    resourceLogs.Resource().Attributes().PutStr("service.name", "windows_dns_client")
    
    // Create scope logs
    scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
    scopeLogs.Scope().SetName("dns.client.events")
    
    // Create log record
    logRecord := scopeLogs.LogRecords().AppendEmpty()
    
    // Set timestamp
    logRecord.SetTimestamp(pcommon.NewTimestampFromTime(event.System.TimeCreated.SystemTime))
    
    // Extract event ID
    eventID := event.System.EventID
    
    // Determine ASIM event type and subtype
    eventType := "Query"
    eventSubType := "request"
    if eventID == 3008 {
        eventSubType = "response"
    } else if eventID == 3020 || eventID == 3019 {
        eventType = "DnsCache"
        if eventID == 3020 {
            eventSubType = "add"
        } else {
            eventSubType = "remove"
        }
    }
    
    // Set ASIM fields
    logRecord.Attributes().PutStr("EventType", eventType)
    logRecord.Attributes().PutStr("EventSubType", eventSubType)
    logRecord.Attributes().PutInt("EventCount", 1)
    logRecord.Attributes().PutStr("EventOriginalType", fmt.Sprintf("%d", eventID))
    logRecord.Attributes().PutStr("EventProduct", "DNS Client")
    logRecord.Attributes().PutStr("EventVendor", "Microsoft")
    
    // Extract DNS-specific fields
    if queryName, ok := event.EventData["QueryName"]; ok {
        logRecord.Attributes().PutStr("DnsQuery", queryName.(string))
    }
    
    if queryType, ok := event.EventData["QueryType"]; ok {
        queryTypeInt, _ := strconv.Atoi(queryType.(string))
        logRecord.Attributes().PutInt("DnsQueryType", int64(queryTypeInt))
        
        // Map query type to name
        queryTypeName := mapQueryTypeName(queryTypeInt)
        logRecord.Attributes().PutStr("DnsQueryTypeName", queryTypeName)
    }
    
    // Extract and map additional fields as needed
    
    return logs
}

func mapQueryTypeName(queryType int) string {
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
```

## DNS Query Type Mapping

DNS Query Types should be mapped to their corresponding names:

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

DNS Response Codes should be mapped to their corresponding names:

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

1. Implement the transformation logic in `asimdns_windows.go`
2. Add comprehensive field mapping for all relevant ASIM fields
3. Develop unit tests for the transformation
4. Add validation to ensure ASIM compatibility
5. Document any limitations or assumptions in the mapping

## References

- [Microsoft Sentinel ASIM DNS Normalization Schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-dns)
- [Windows DNS Client ETW Provider](https://docs.microsoft.com/en-us/windows/win32/wec/windows-event-channels-for-services-and-drivers)
- [DNS Protocol RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)

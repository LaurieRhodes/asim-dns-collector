# ASIM DNS Transformation Architecture

## Overview
This document outlines the architecture for transforming Windows DNS Client ETW events into the Microsoft Sentinel ASIM DNS Activity Logs schema. It provides details on the implemented transformation layer in the ASIM DNS Collector.

## Transformation Flow

```
┌─────────────────┐    ┌───────────────────┐    ┌─────────────────────┐    ┌───────────────┐
│                 │    │                   │    │                     │    │               │
│ Windows DNS ETW │ -> │ OTel Receiver     │ -> │ ASIM Transformation │ -> │ Kafka Export  │
│ Events          │    │ (asimdns)         │    │ Layer               │    │ (Event Hubs)  │
│                 │    │                   │    │                     │    │               │
└─────────────────┘    └───────────────────┘    └─────────────────────┘    └───────────────┘
```

## Key Components

### 1. ETW Event Capture
Implemented in `asimdns_windows.go` using the golang-etw library. This captures raw Windows DNS Client events with various fields in the OpenTelemetry format.

### 2. Transformation Layer
Implemented in the `convertEventToLogs` function in `asimdns_windows.go`. This layer:
- Identifies event types and maps to ASIM event categories
- Extracts and transforms fields from ETW to ASIM schema
- Adds derived and default values for required ASIM fields
- Enriches with system information (hostname, IP, etc.)

### 3. Export Layer
Implemented using the Kafka exporter to send data to Azure Event Hubs, which integrates with Microsoft Sentinel.

## Implemented Transformation Layer

### Component Structure
The transformation layer is implemented with a modular approach in `asimdns_windows.go`:

1. **Main Transformation Function**: `convertEventToLogs`
2. **Event Classification**: `getAsimEventType`
3. **Device Field Mapping**: `setDeviceFields`
4. **Network Field Mapping**: `setNetworkFields`
5. **Response Field Mapping**: `setResponseFields`
6. **DNS Flags Handling**: `setDnsFlags`
7. **Additional Fields**: `setAdditionalFields`
8. **Helper Functions**: Type mapping and utility functions

### Event Type Mapping

The implemented transformation maps ETW event IDs to ASIM event types:

| EventID | ASIM EventType | ASIM EventSubType |
|---------|--------------|------------------|
| 3006    | Query        | request          |
| 3008    | Query        | response         |
| 3020    | DnsCache     | add              |
| 3019    | DnsCache     | remove           |
| Other   | Info         | status           |

### Field Mapping Implementation

The transformation maps ETW fields to ASIM schema fields:

#### Core Fields
- EventType, EventSubType based on ETW event ID
- EventProduct set to "DNS Client"
- EventVendor set to "Microsoft"
- EventOriginalType set to the original ETW event ID
- EventResult based on DNS status code (for responses)

#### DNS-Specific Fields
- DnsQuery from ETW QueryName field
- DnsQueryType from ETW QueryType field
- DnsQueryTypeName mapped from the numeric type
- DnsResponseCode from ETW Status/QueryStatus field
- DnsResponseName mapped from the response code
- DnsFlags extracted from ETW QueryOptions

#### Device and Network Fields
- DvcHostname, Dvc set to local hostname
- DvcOs set to "Windows"
- DvcOsVersion from Windows version information
- SrcIpAddr set to local IP address
- DstIpAddr from ETW ServerList field
- DstPortNumber set to 53 (standard DNS port)
- SrcProcessId from ETW process ID

#### Additional Data
- AdditionalFields contains JSON-encoded non-standard fields

## Configuration and Performance

### Error Handling
The implementation includes robust error handling:

1. Safe type conversion with fallbacks
2. Graceful handling of missing fields
3. Default values for required fields
4. Optional debug logging for troubleshooting

### Performance Optimizations
The implementation includes several performance considerations:

1. Minimized memory allocations
2. Efficient string handling
3. Conditional processing based on event type
4. Careful type handling to avoid unnecessary conversions

## Integration with Microsoft Sentinel

### ASIM Schema Alignment
The transformed events align with Microsoft Sentinel's ASIM DNS Activity Logs schema:

1. Standard field naming conventions
2. Proper field types and formats
3. Required fields always populated
4. Optional fields included when data is available

### Future Refinements
For perfect alignment with Microsoft's native ASIM format, consider:

1. Field format adjustments based on observed Microsoft output
2. Addition of any missing optional fields
3. Validation against Microsoft's schema documentation
4. Timestamp format verification

## Testing and Validation

### Implemented Testing
The implementation includes unit tests for:

1. Event type mapping functions
2. DNS query type and response code mapping
3. DNS flags extraction
4. Safe field access and transformation

### Recommended Additional Testing
For comprehensive validation:

1. Field-by-field comparison with Microsoft's native ASIM format
2. Schema validation testing
3. Performance testing with high event volumes
4. Edge case handling validation

## Future Enhancements

The following enhancements could further improve the implementation:

1. **Geo-IP Enrichment**: Add geographic information for IP addresses
2. **DNS Response Content Parsing**: Extract and decode DNS response data
3. **ASIM Field Expansion**: Support more optional ASIM fields
4. **Context Correlation**: Link related DNS events together
5. **Custom Field Mapping**: Allow user-defined field mappings
6. **Configuration Options**: Add customization for transformation behavior

## Conclusion

The implemented transformation layer successfully converts Windows DNS Client ETW events to the Microsoft Sentinel ASIM DNS Activity Logs schema. The modular design provides a solid foundation for future refinements and enhancements to achieve perfect alignment with Microsoft's native ASIM format.

The implementation prioritizes:
- Accurate mapping to the ASIM schema
- Comprehensive coverage of DNS events
- Efficient processing for production use
- Robust error handling
- Maintainable code structure

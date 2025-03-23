# DNS Server Configuration Guide

## Overview

The ASIM DNS Collector can now collect DNS Server events in addition to DNS Client events. This document explains how to configure the collector to capture DNS Server events for improved visibility into remote DNS lookups.

## Background

Previously, the ASIM DNS Collector was configured to only collect DNS Client events using the `Microsoft-Windows-DNS-Client` ETW provider with GUID `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`. This configuration only captured local DNS lookups initiated by the client system.

To capture remote lookups coming into a DNS Server, we need to use the `Microsoft-Windows-DNSServer` ETW provider with GUID `{EB79061A-A566-4698-9119-3ED2807060E7}`.

## Available DNS Server Event Types

The DNS Server provider exposes numerous event types through keywords. The most relevant ones for DNS activity monitoring are:

| Keyword Value | Event Type |
|---------------|------------|
| 0x0000000000000001 | QUERY_RECEIVED |
| 0x0000000000000002 | RESPONSE_SUCCESS |
| 0x0000000000000004 | RESPONSE_FAILURE |
| 0x0000000000000008 | IGNORED_QUERY |
| 0x0000000000000010 | RECURSE_QUERY_OUT |
| 0x0000000000000020 | RECURSE_RESPONSE_IN |

## Configuration

### DNS Server Configuration File

A new configuration file `dns_server_config.yaml` has been created specifically for DNS Server event collection. This file contains optimized settings for DNS Server events:

```yaml
receivers:
  asimdns:
    # ETW session name
    session_name: "DNSServerTrace"
    # DNS Server Provider Configuration - Microsoft-Windows-DNSServer
    provider_guid: "{EB79061A-A566-4698-9119-3ED2807060E7}"
    # Combined flags for query-related events
    enable_flags: 0x000000000000003F
    # Information level (4 is Informational, 5 is Verbose)
    enable_level: 4
    
    # Include info events for DNS Server
    include_info_events: true
    # No excluded event IDs by default for DNS Server
    excluded_event_ids: []
```

### Event Type Mapping

DNS Server events are mapped to the ASIM schema as follows:

| DNS Server Event | ASIM EventType | ASIM EventSubType |
|------------------|----------------|-------------------|
| Query received (256, 257) | Query | request |
| Response events (258, 259) | Query | response |
| Recursion events (260, 261) | Query | recursive |
| Other events | Info | status |

### Field Mapping

DNS Server events contain different field names than DNS Client events. The mapping to ASIM schema is as follows:

| DNS Server Field | ASIM Field |
|------------------|------------|
| QNAME | DnsQuery |
| QTYPE | DnsQueryType |
| RCODE | DnsResponseCode |
| Source | SrcIpAddr |
| Destination | DstIpAddr |
| Port | SrcPortNumber |
| Zone | DnsZone |
| TCP | NetworkProtocol (converted to TCP/UDP) |
| RD | DnsFlagsRecursionDesired |
| AA | DnsFlags (added as "AA") |
| AD | DnsFlags (added as "AD") |

## ASIM Schema Compliance

The collector has been updated to ensure that DNS Server events comply with the Microsoft ASIM schema requirements:

1. **ObservedTimestamp**: Now properly set to capture time
2. **EventCount**: Set to 1 for all events
3. **DnsSessionId**: Generated unique ID combining process ID, event ID, and timestamp
4. **Device fields**: Proper population of DvcHostname, DvcId, and other device info
5. **Network fields**: Proper extraction of source/destination IP addresses and ports
6. **DNS flags**: Extraction and formatting of DNS flags according to ASIM schema

## Usage

### Running with DNS Server Configuration

To run the ASIM DNS Collector with DNS Server event collection:

```powershell
.\asim-dns-collector.exe --config=.\configs\dns_server_config.yaml
```

### Validating Events

To validate that DNS Server events are being collected correctly:

1. Start the collector with the DNS Server configuration
2. Generate DNS traffic to the server (e.g., by performing DNS lookups)
3. Check the logs to see if events are being captured
4. Verify that the events contain the expected fields

You can add debugging by using the logging exporter included in the configuration:

```yaml
exporters:
  logging:
    verbosity: detailed
    sampling_initial: 1
    sampling_thereafter: 1

service:
  pipelines:
    logs/dns_server:
      exporters: [kafka, logging]
```

## Troubleshooting

### Common Issues

1. **No events captured**: Ensure the DNS Server service is running and that the process has appropriate permissions
2. **Permission issues**: The collector must run with administrative privileges to capture ETW events
3. **Event format issues**: If events are captured but don't contain expected fields, check that the correct provider GUID is being used
4. **Timestamp issues**: If you see events with incorrect timestamps (e.g., 1970-01-01), make sure you're running the updated version

### Stopping Existing Traces

Before starting the collector, ensure no other traces are running against the DNS Server:

```cmd
logman query -ets | findstr /i DNS
```

If you find any running traces, stop them:

```cmd
logman stop "TRACE_NAME" -ets
```

To automatically clean up all DNS-related traces:

```cmd
for /f "tokens=1" %i in ('logman query -ets ^| findstr /i DNS') do @logman stop "%i" -ets
```

### Using Logman for Diagnostics

The `logman` command can be used to check available providers and their settings:

```powershell
# List all providers
logman query providers

# Check specific provider details
logman query providers "Microsoft-Windows-DNSServer"

# Test provider capture (requires admin privileges)
logman create trace -n DNSServerTest -o dnsserver.etl -p "Microsoft-Windows-DNSServer" 0x3F 4
logman start DNSServerTest
# Generate some DNS traffic
logman stop DNSServerTest

# View captured events
tracerpt dnsserver.etl
```

## Additional Notes

- DNS Server events provide better visibility into external DNS queries compared to DNS Client events
- The DNS Server provider may generate a higher volume of events in busy environments; adjust filtering as needed
- For comprehensive DNS monitoring, consider running both DNS Client and DNS Server collectors
- The collector automatically extracts fields like client IP, server IP, and query details for proper ASIM schema compliance

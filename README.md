# ASIM DNS Collector

## Project Overview

A custom OpenTelemetry Collector receiver for capturing and transforming Windows DNS Server and Client events into Microsoft Sentinel ASIM (Advanced Security Information Model) schema. The collector successfully captures DNS events via ETW and exports them to Azure Event Hubs using the Kafka protocol.

### Key Features

- Pure Go implementation with no CGO dependencies
- Windows DNS Server and Client event capture using ETW
- Real-time event processing and transformation
- Comprehensive filtering capabilities to improve signal-to-noise ratio
- OpenTelemetry Collector integration
- Kafka exporter for Microsoft Sentinel integration via Azure Event Hubs

## Current Status

- ✅ ETW event capture is fully functional
- ✅ OpenTelemetry Collector receiver implementation is complete
- ✅ Successful export to Azure Event Hubs using Kafka protocol
- ✅ ASIM schema transformation for DNS Server and Client events
- ✅ Configurable filtering for high-volume environments
- ✅ Field mapping from ETW events to ASIM DNS Activity Logs schema

## Quick Start Guide

### Installation

1. Download the latest release from the releases page
2. Create a directory for the collector (e.g., `C:\Program Files\ASIMDNSCollector`)
3. Extract the release package to this directory
4. Configure your Event Hub details in the configuration file

### Running as Administrator

The collector must be run with administrative privileges to access ETW:

```powershell
# Open PowerShell as Administrator
cd "C:\Program Files\ASIMDNSCollector"
.\asim-dns-collector.exe --config=.\configs\dns_server_config.yaml
```

### Installing as a Windows Service

For production environments, install as a Windows service:

```powershell
# Install service (run as Administrator)
sc create ASIMDNSCollector binPath= "\"C:\Program Files\ASIMDNSCollector\asim-dns-collector.exe\" --config=\"C:\Program Files\ASIMDNSCollector\configs\dns_server_config.yaml\"" start= auto
sc description ASIMDNSCollector "ASIM DNS Collector Service for Microsoft Sentinel"

# Start the service
sc start ASIMDNSCollector
```

For detailed installation instructions, see [INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md).

## Architecture

- Pure Go ETW event collection via golang-etw
- Modular OpenTelemetry Collector receiver
- Flexible event processing and filtering
- Microsoft Sentinel ASIM schema transformation
- Azure Event Hubs integration using Kafka protocol

## ASIM DNS Schema Integration

The collector transforms Windows DNS Server and Client ETW events into the Microsoft Sentinel ASIM DNS Activity Logs schema. This standardized schema enables consistent analytics and threat detection across different DNS data sources.

### Key ASIM DNS Fields Mapping

| ASIM Field        | Description                       | DNS Server Source | DNS Client Source |
| ----------------- | --------------------------------- | ----------------- | ----------------- |
| TimeGenerated     | Time of the event                 | Event timestamp   | Event timestamp   |
| EventType         | Type of event (Query, Response)   | Based on EventID  | Based on EventID  |
| EventSubType      | Subtype (request, response)       | Based on EventID  | Based on EventID  |
| EventResult       | Result of the operation           | Based on RCODE    | Based on Status   |
| DnsQuery          | The DNS query                     | QNAME             | QueryName         |
| DnsQueryType      | Type of DNS query (A, AAAA, etc.) | QTYPE             | QueryType         |
| SrcIpAddr         | Source IP address                 | CLIENT_IP         | Local IP          |
| SrcPortNumber     | Source port                       | Port              | SourcePort        |
| DstIpAddr         | Destination IP address            | Server IP         | ServerList        |
| EventOriginalType | Original event ID                 | event.id          | event.id          |
| EventProduct      | Product generating the event      | "DNS Server"      | "DNS Client"      |
| EventVendor       | Vendor of the product             | "Microsoft"       | "Microsoft"       |

For more details on the schema mapping, see [ASIM_SCHEMA_MAPPING.md](docs/ASIM_SCHEMA_MAPPING.md).

## Project Structure

- `cmd/`: Collector executable entry point
- `internal/receiver/asimdns/`: Custom receiver implementation
- `configs/`: Configuration templates
- `docs/`: Project documentation

## Configuration

Choose the appropriate configuration file based on your needs:

- `dns_server_config.yaml`: Collect events from the DNS Server
- `config.yaml`: Collect events from DNS Client
- `config_with_filtering.yaml`: DNS Client with comprehensive filtering
- `dns_server_debug_config.yaml` and `debug_config.yaml`: Debug configurations

Example configuration for DNS Server with Azure Event Hubs integration:

```yaml
receivers:
  asimdns:
    session_name: "DNSServerTrace"
    provider_guid: "{EB79061A-A566-4698-9119-3ED2807060E7}"
    enable_flags: 0x000000000000003F
    enable_level: 4

    # Filtering options
    include_info_events: true
    excluded_domains:
      - "*.opinsights.azure.com"
      - "*.internal.cloudapp.net"
    enable_deduplication: true
    deduplication_window: 300

exporters:
  kafka:
    brokers: ["your-eventhub-namespace.servicebus.windows.net:9093"]
    protocol_version: "2.0.0"
    topic: "asimdnsactivitylogs"
    encoding: otlp_json
    auth:
      sasl:
        mechanism: PLAIN
        username: "$ConnectionString"
        password: "Endpoint=sb://your-eventhub-namespace.servicebus.windows.net/;SharedAccessKeyName=Send;SharedAccessKey=yourkey;EntityPath=youreventhubname"
      tls:
        insecure: false
```

## DNS Event Types

The collector captures various Windows DNS events, including:

### DNS Server Events

- **256, 257**: DNS query received
- **258, 259**: DNS response events
- **260, 261**: DNS recursion events

### DNS Client Events

- **3006**: DNS query sent
- **3008**: DNS query response received
- **3020**: DNS cache entry added
- **3019**: DNS cache entry removed

## Documentation

- [INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md): Detailed installation instructions
- [DNS_SERVER_CONFIGURATION.md](docs/DNS_SERVER_CONFIGURATION.md): DNS Server specific configuration
- [FILTERING_USAGE.md](docs/FILTERING_USAGE.md): Guide to optimizing event filtering
- [ASIM_SCHEMA_MAPPING.md](docs/ASIM_SCHEMA_MAPPING.md): Details on ASIM schema mapping
- [ETW_INTEGRATION.md](docs/ETW_INTEGRATION.md): Technical details on ETW integration
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): Help with common issues

## Technical Implementation

The ASIM DNS Collector uses:

- [golang-etw](https://github.com/0xrawsec/golang-etw) for ETW integration
- OpenTelemetry Collector framework for processing and exporting
- Producer-consumer model for event handling
- Azure Event Hubs with Kafka protocol for Sentinel integration

## Building from Source

If you need to build from source:

```bash
# Install OpenTelemetry Collector Builder
go install go.opentelemetry.io/collector/cmd/builder@v0.89.0

# Build the collector
builder --config builder-config.yaml
```



## License

MIT License

## Acknowledgments

- OpenTelemetry Community
- Microsoft Sentinel Team
- golang-etw Project

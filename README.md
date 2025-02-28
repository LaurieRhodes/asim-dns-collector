# ASIM DNS Collector

## Project Overview

A custom OpenTelemetry Collector receiver for capturing and transforming Windows DNS Client events into Microsoft Sentinel ASIM (Advanced Security Information Model) schema. The collector successfully captures DNS events via ETW and exports them to Azure Event Hubs using the Kafka protocol.

### Key Features

- Pure Go implementation with no CGO dependencies
- Windows DNS Client event capture using ETW
- Real-time event processing and transformation
- OpenTelemetry Collector integration
- Kafka exporter for Microsoft Sentinel integration via Azure Event Hubs

## Current Status

- ✅ ETW event capture is fully functional
- ✅ OpenTelemetry Collector receiver implementation is complete
- ✅ Successful export to Azure Event Hubs using Kafka protocol
- 🔄 ASIM schema transformation in progress
- 🔄 Field mapping from ETW events to ASIM DNS Activity Logs schema

## Architecture

- Pure Go ETW event collection via golang-etw
- Modular OpenTelemetry Collector receiver
- Flexible event processing and filtering
- Microsoft Sentinel ASIM schema transformation
- Azure Event Hubs integration using Kafka protocol

## ASIM DNS Schema Integration

The collector transforms Windows DNS Client ETW events into the Microsoft Sentinel ASIM DNS Activity Logs schema. This standardized schema enables consistent analytics and threat detection across different DNS data sources.

### Key ASIM DNS Fields Mapping

| ASIM Field        | Description                       | ETW Source Field       |
| ----------------- | --------------------------------- | ---------------------- |
| TimeGenerated     | Time of the event                 | Event timestamp        |
| EventType         | Type of event (Query, Response)   | Based on EventID       |
| EventSubType      | Subtype (request, response)       | Based on EventID       |
| EventResult       | Result of the operation           | Based on response code |
| DnsQuery          | The DNS query                     | dns.QueryName          |
| DnsQueryType      | Type of DNS query (A, AAAA, etc.) | dns.QueryType          |
| SrcIpAddr         | Source IP address                 | Based on context       |
| SrcPortNumber     | Source port                       | Based on context       |
| DstIpAddr         | Destination IP address            | Based on context       |
| EventOriginalType | Original event ID                 | event.id               |
| EventProduct      | Product generating the event      | "DNS Client"           |
| EventVendor       | Vendor of the product             | "Microsoft"            |

### ASIM Schema Reference

The full ASIM DNS Activity Logs schema includes numerous fields for comprehensive DNS event representation, including query details, network information, threat intelligence, and more.

## Project Structure

- `cmd/`: Collector executable entry point
- `internal/receiver/asimdns/`: Custom receiver implementation
- `configs/`: Configuration templates
- `docs/`: Project documentation

## Getting Started

### Prerequisites

- Go 1.21+
- OpenTelemetry Collector Builder
- Windows environment (for DNS event capture)
- Azure Event Hubs namespace (for Kafka protocol export)

### Installation

1. Clone the repository
2. Install OpenTelemetry Collector Builder
3. Build the collector
   
   ```bash
   go install go.opentelemetry.io/collector/cmd/builder@v0.89.0
   builder --config builder-config.yaml
   ```

### Configuration

Customize `configs/config.yaml` to configure:

- ETW provider settings
- Event filtering
- Export destinations

Example configuration for Azure Event Hubs integration:

```yaml
receivers:
  asimdns:
    session_name: "DNSClientTrace"
    provider_guid: "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
    enable_flags: 0x8000000000000FFF
    enable_level: 5
    buffer_size: 64
    min_buffers: 64
    max_buffers: 128

exporters:
  kafka:
    brokers: ["your-eventhub-namespace.servicebus.windows.net:9093"]
    protocol_version: "2.0.0"
    topic: "youreventhubname"
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

The collector captures various Windows DNS Client events, including:

- **3006**: DNS query sent
- **3008**: DNS query response received
- **3020**: DNS cache entry added
- **3019**: DNS cache entry removed

## Next Steps

1. Complete ASIM schema transformation layer
2. Implement comprehensive field mapping
3. Add validation and error handling for ASIM schema compliance
4. Develop unit and integration tests for transformation logic
5. Optimize performance for high-volume event processing

## Technical Implementation

The ASIM DNS Collector uses:

- [golang-etw](https://github.com/0xrawsec/golang-etw) for ETW integration
- OpenTelemetry Collector framework for processing and exporting
- Producer-consumer model for event handling
- Azure Event Hubs with Kafka protocol for Sentinel integration

## Contributing

Please read the documentation for details on our code of conduct and the process for submitting pull requests.

## License

MIT License

## Acknowledgments

- OpenTelemetry Community
- Microsoft Sentinel Team
- golang-etw Project

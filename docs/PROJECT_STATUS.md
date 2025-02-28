# ASIM DNS Collector Project Status

## Overview
This document provides the current status of the ASIM DNS Collector project, highlighting recent milestones, current work, and planned future developments.

## Current Status (February 27, 2025)

### Recently Completed
- ✅ **ETW Event Capture**: Successfully implemented Windows DNS Client event capture using the golang-etw library
- ✅ **OpenTelemetry Collector Integration**: Completed custom receiver implementation
- ✅ **Azure Event Hubs Integration**: Successfully exporting data to Event Hubs via Kafka protocol
- ✅ **ASIM Schema Transformation**: Implemented transformation from ETW events to Microsoft Sentinel ASIM DNS Activity Logs schema
- ✅ **Field Mapping**: Successfully mapped ETW fields to ASIM schema with proper type conversions

### In Progress
- 🔄 **Event Filtering Implementation**: Developing filtering capabilities to reduce volume and increase signal-to-noise ratio
- 🔄 **Configuration Extension**: Adding configuration options for domain filtering and event type selection
- 🔄 **Performance Optimization**: Enhancing throughput for high-volume DNS environments
- 🔄 **Query Deduplication**: Adding mechanisms to reduce redundant events

### Planned Next
- 📋 **Testing Framework**: Develop comprehensive testing for transformation and filtering logic
- 📋 **Production Hardening**: Enhance error handling and recovery mechanisms
- 📋 **Documentation Updates**: Update documentation to reflect filtering capabilities
- 📋 **Statistical Analysis**: Add capabilities to identify anomalous DNS patterns

## Current Challenges

### High Data Volume
Testing has revealed that the collector generates a high volume of events (8,000+ in 2 hours from a single server), including many that have limited security value:

1. **Repetitive events**: Many status events (EventIDs 1001, 1015, 1016, 1019) provide minimal security context
2. **Polling queries**: Regular repeated DNS queries to the same domains
3. **Internal operational traffic**: System maintenance and monitoring queries
4. **Duplicate query types**: Both A and AAAA records for the same domains

### Filtering Requirements
To address data volume concerns, we need to implement filtering capabilities:

1. **Event Type Filtering**: Option to exclude specific event types with low security value
2. **Domain Filtering**: Capability to exclude routine operational domains
3. **Rate Limiting**: Deduplication of repetitive queries within a configurable time window
4. **Configuration-driven**: All filtering should be configurable without code changes

## Planned Filtering Implementation

### Domain Exclusion
```yaml
receivers:
  asimdns:
    # Existing configuration...
    
    # Domain exclusion patterns
    excluded_domains:
      - "*.opinsights.azure.com"
      - "*.internal.cloudapp.net"
      - "wpad*"
```

### Event Type Filtering
```yaml
receivers:
  asimdns:
    # Existing configuration...
    
    # Event type exclusion
    include_info_events: false  # Exclude EventType "Info" events
    excluded_event_ids: [1001, 1019]  # Specific IDs to exclude
```

### Query Deduplication
```yaml
receivers:
  asimdns:
    # Existing configuration...
    
    # Deduplication settings
    enable_deduplication: true
    deduplication_window: 300  # seconds
```

## Next Implementation Steps

1. **Filtering Framework**: Implement a modular filtering framework in the receiver
2. **Configuration Extension**: Add filtering options to the configuration structure
3. **Domain Pattern Matching**: Develop efficient wildcard/pattern matching for domains
4. **Deduplication Cache**: Implement an efficient caching mechanism for recent queries
5. **Performance Testing**: Measure impact of filtering on throughput and CPU/memory usage

## Milestone Achievements

### Milestone 1: Event Collection ✅
- ETW-based event capture implementation
- Windows DNS Client provider integration
- Real-time event streaming

### Milestone 2: Export Integration ✅
- Azure Event Hubs integration via Kafka protocol
- Event serialization and formatting
- Authentication and secure transmission

### Milestone 3: ASIM Transformation ✅
- Field mapping implementation complete
- Type conversion logic implemented
- Multi-event type support (Query request/response, DnsCache add/remove)

### Milestone 4: Filtering & Optimization 🔄
- Implementing domain filtering
- Adding event type exclusions
- Developing query deduplication
- Performance optimization

## Reference Materials
- Microsoft Sentinel ASIM DNS Activity Logs schema
- Windows DNS Client ETW provider documentation
- OpenTelemetry Collector exporter configuration
- Azure Event Hubs for Apache Kafka documentation

## Team Notes
The project has successfully implemented the core ASIM transformation functionality, and focus is now shifting to optimizing the event collection for security operations. Initial testing shows high event volumes that include many routine operational events with limited security value. The next development phase will focus on implementing intelligent filtering to improve the signal-to-noise ratio while preserving security-relevant information.

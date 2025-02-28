# ASIM DNS Collector Refactoring Guide

## Overview

This document explains the refactoring applied to the ASIM DNS Collector, detailing the changes in code structure and how to navigate the refactored codebase.

## Motivation for Refactoring

The original implementation had several limitations:

1. **Large, Monolithic File**: The main implementation file (`asimdns_windows.go`) was very large, making it difficult to maintain and evolve.
2. **Limited Separation of Concerns**: The filtering, transformation, and collection logic were tightly coupled.
3. **Complex Thread Safety**: Concurrency handling was scattered throughout the code.
4. **Limited Debugging Capabilities**: Not enough visibility into filtering statistics and event flow.

## Refactored Code Structure

### File Organization

The code has been reorganized into smaller, more focused files:

| File                 | Description                                                      |
| -------------------- | ---------------------------------------------------------------- |
| `asimdns.go`         | Core configuration structure and non-Windows stub implementation |
| `asimdns_windows.go` | Windows-specific ETW implementation                              |
| `helpers.go`         | General helper functions for device information                  |
| `dns_helpers.go`     | DNS-specific helper functions                                    |

### Modular Design

The implementation has been reorganized to:

1. **Separate Concerns**: Each file focuses on a specific aspect of functionality
2. **Improve Clarity**: Smaller files with focused responsibility
3. **Facilitate Testing**: Easier to test individual components
4. **Enable AI Development**: More manageable for AI tools to assist with development

## Key Changes

### 1. Filtering Logic

The filtering logic has been reorganized into a modular structure:

- **Event Type Filtering**: Handles filtering based on event types and IDs
- **Domain Pattern Filtering**: Manages pattern-based domain filtering
- **Query Type Filtering**: Manages filtering of specific query types (e.g., AAAA records)
- **Deduplication**: Manages time-based query deduplication

### 2. Enhanced Statistics and Logging

Added comprehensive statistics and improved logging:

- **Event Counters**: Track total and filtered events
- **Periodic Stats Output**: Log statistics at regular intervals
- **Detailed Debugging**: More detailed logs for troubleshooting

### 3. Improved Thread Safety

Enhanced concurrency handling:

- **Dedicated Mutexes**: Each shared data structure has its own mutex
- **Read/Write Locks**: Using RWMutex for better performance when appropriate
- **Atomic Counters**: For high-performance counter operations

### 4. Configuration Validation

Improved configuration validation:

- **Default Values**: Better handling of default configuration values
- **Validation Logic**: More comprehensive validation of configuration options
- **Debugging Configuration**: Added specific debug configuration

## Navigating the Code

### Main Flow

The main event processing flow remains:

1. **Initialization**: `newDNSEtwReceiver` creates and configures the receiver
2. **Start**: The `Start` method initializes the ETW session and consumer
3. **Event Processing**: The ETW event callback calls `convertEventToLogs`
4. **Filtering**: The `shouldFilter` method applies all filtering logic
5. **Transformation**: Event data is transformed to ASIM schema
6. **Export**: Transformed logs are sent to the consumer

### Filtering Flow

The filtering flow has been reorganized:

1. **shouldFilter**: Master method that orchestrates all filtering
2. **shouldFilterEventID**: Filters based on event type and ID
3. **shouldFilterDomain**: Filters based on domain patterns
4. **isAAAARecord**: Filters AAAA records if configured
5. **isDuplicateQuery**: Filters duplicate queries within time window

## Debugging and Monitoring

The refactored code includes improved debugging and monitoring:

1. **Event Statistics**: Regular logging of event statistics
2. **Filter Metrics**: Detailed metrics on filtering effectiveness
3. **Initialization Logs**: More detailed logs during initialization
4. **Debug Configuration**: Specific configuration for debugging

## Migration Guide

If you've made custom modifications to the original code:

1. **Identify Feature Area**: Determine which file now contains the feature
2. **Review Changes**: Compare original vs. refactored implementation
3. **Apply Modifications**: Apply your changes to the appropriate file
4. **Test Thoroughly**: Ensure functionality is preserved

## Benefits of Refactoring

The refactored code provides several benefits:

1. **Better Maintainability**: Smaller, focused files are easier to maintain
2. **Enhanced Extensibility**: Easier to add new features or modify existing ones
3. **Improved Visibility**: Better logging and statistics
4. **Better Performance**: Optimized filtering and thread safety
5. **AI Development Friendly**: Structure works better with AI development tools

## Example: Adding a New Filter Type

To add a new filter type, follow this pattern:

1. **Define Filter Logic**: Add a new method in `asimdns_windows.go`:
   
   ```go
   func (r *DNSEtwReceiver) shouldFilterNewType(event *etw.Event) bool {
       // Implement filter logic
       return false
   }
   ```

2. **Update Config**: Add configuration options in `asimdns.go`:
   
   ```go
   type Config struct {
       // ...existing fields
       EnableNewFilter bool `mapstructure:"enable_new_filter"`
   }
   ```

3. **Add to Main Filter**: Update the `shouldFilter` method:
   
   ```go
   func (r *DNSEtwReceiver) shouldFilter(event *etw.Event) bool {
       // Existing filter calls
   
       // New filter
       if r.config.EnableNewFilter && r.shouldFilterNewType(event) {
           return true
       }
   
       return false
   }
   ```

4. **Update Documentation**: Document the new filter option

# ASIM Alignment Guide

## Overview

This guide provides recommendations for fine-tuning the ASIM DNS Collector's output to perfectly match Microsoft Sentinel's native ASIM format. While the current implementation successfully transforms ETW events to the ASIM schema, some refinements may be needed to ensure exact compatibility with Microsoft's implementation.

## Comparing with Native ASIM Format

To verify alignment with Microsoft's native ASIM format:

1. **Obtain Sample Data**: Collect sample data from both:
   - The ASIM DNS Collector output
   - Microsoft Sentinel's native ASIM-formatted DNS logs

2. **Field-by-Field Comparison**: Compare each field for:
   - Field names (exact case and spelling)
   - Data types and formats
   - Default values for missing data
   - Array and object serialization format

3. **Identify Discrepancies**: Note any differences, particularly in:
   - Timestamp formats
   - Enumerated values (e.g., event types, result codes)
   - Field presence and required status
   - String format conventions

## Common Alignment Issues

### 1. Timestamp Formats

Microsoft Sentinel may expect specific timestamp formats:

```go
// Current implementation
logRecord.SetTimestamp(pcommon.NewTimestampFromTime(event.System.TimeCreated.SystemTime))

// Potential refinement
timeStr := event.System.TimeCreated.SystemTime.Format(time.RFC3339Nano)
logRecord.Attributes().PutStr("TimeGenerated", timeStr)
```

### 2. Field Naming Conventions

Verify exact field names match Microsoft's convention:

```go
// Example field name verification
// Microsoft may use "DvcId" instead of "DvcID"
logRecord.Attributes().PutStr("DvcId", deviceId) // Note the capitalization
```

### 3. Enumerated Values

Ensure enumerated values match Microsoft's expected values:

```go
// Example for EventResult
// Microsoft might expect "Success" or "Succeeded" specifically
if statusInt == 0 {
    logRecord.Attributes().PutStr("EventResult", "Success") // Verify exact string
}
```

### 4. Required vs. Optional Fields

Microsoft may treat certain fields as required that we consider optional:

```go
// Example for ensuring a required field
// If Microsoft requires "EventSchemaVersion" but we don't set it
logRecord.Attributes().PutStr("EventSchemaVersion", "0.1.0")
```

## Testing Alignment

### 1. Ingestion Testing

Test ingestion into Microsoft Sentinel:

1. Export transformed data to Azure Event Hubs
2. Configure Microsoft Sentinel to ingest the data
3. Verify data appears correctly in Sentinel
4. Check for parser or schema warnings/errors

### 2. Query Testing

Test Microsoft Sentinel queries against the data:

1. Run standard ASIM queries against your data
2. Compare results with queries against native ASIM data
3. Verify fields are accessible and formatted as expected

### 3. Analytical Rule Testing

Test Microsoft Sentinel analytical rules:

1. Apply standard DNS analytical rules
2. Verify rules trigger as expected
3. Check entity mapping and correlation

## Refinement Strategy

### 1. Incremental Improvements

Make targeted changes for specific fields:

```go
// Example adjustment for a specific field
// If Microsoft expects "DnsQueryClass" as an int but we're using string
if queryClass, ok := getEventDataString(event, "QueryClass"); ok {
    if classInt, err := strconv.Atoi(queryClass); err == nil {
        logRecord.Attributes().PutInt("DnsQueryClass", int64(classInt))
    }
}
```

### 2. Configuration Options

Add configuration options for alignment settings:

```yaml
receivers:
  asimdns:
    # ... existing configuration ...
    asim_alignment:
      timestamp_format: "RFC3339"
      required_fields: ["EventSchemaVersion", "AdditionalFields"]
      event_result_values:
        success: "Success"  # Microsoft's expected value
        failure: "Failure"  # Microsoft's expected value
```

### 3. Validation Layer

Add a validation layer to ensure output matches expectations:

```go
// Example validation function
func validateAsimCompliance(logRecord plog.LogRecord) error {
    // Check required fields
    requiredFields := []string{"TimeGenerated", "EventType", "EventProduct"}
    for _, field := range requiredFields {
        if _, ok := logRecord.Attributes().Get(field); !ok {
            return fmt.Errorf("missing required field: %s", field)
        }
    }
    
    // Validate field formats
    // ...
    
    return nil
}
```

## Microsoft ASIM Reference

To ensure perfect alignment, consult these Microsoft references:

1. [ASIM DNS Normalization Schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-dns)
2. [ASIM Schema Reference](https://learn.microsoft.com/en-us/azure/sentinel/normalization-about-schemas)
3. [ASIM Parsers in GitHub](https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/ASimDns)

## Recommended Next Steps

1. **Sample Data Collection**: Gather sample data from both your collector and Microsoft's native format
2. **Detailed Comparison**: Perform detailed field-by-field comparison
3. **Targeted Refinements**: Make specific adjustments based on findings
4. **Validation Testing**: Develop validation tests for schema compliance
5. **Documentation Update**: Document any specific alignment considerations

## Conclusion

Achieving perfect alignment with Microsoft's native ASIM format ensures the ASIM DNS Collector integrates seamlessly with Microsoft Sentinel's analytics, detection, and threat hunting capabilities. By following this guide, you can fine-tune the implementation to match Microsoft's expectations exactly, enabling the full power of standardized security data for DNS monitoring.

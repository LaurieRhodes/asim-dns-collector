# ASIM DNS Collector Troubleshooting Guide

## Common Issues

### No Events Being Processed

**Symptom:** Collector starts successfully but no events are being sent to Event Hub. Console shows the following and then appears to hang:

```
2025-02-27T02:12:08.603Z        info    asimdns@v0.1.0/asimdns_windows.go:110   ASIM DNS ETW receiver started   {"kind": "receiver", "name": "asimdns", "data_type": "logs", "provider": "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}", "level": 5, "keywords": 9223372036854779903, "filtering_enabled": true}
2025-02-27T02:12:08.606Z        info    healthcheck/handler.go:132      Health Check state change   {"kind": "extension", "name": "health_check", "status": "ready"}
2025-02-27T02:12:08.606Z        info    service@v0.89.0/service.go:169  Everything is ready. Begin running and processing data.
```

**Potential Causes:**

1. **ETW Session Configuration**: The ETW session isn't receiving events from the DNS Client provider.
2. **Over-aggressive Filtering**: The filtering is too aggressive and is filtering out all events.
3. **Initialization Issue**: The ETW consumer is not properly initialized.
4. **DNS Client Event Generation**: No DNS client events are being generated on the system.

**Troubleshooting Steps:**

1. **Use Debug Configuration**: Run the collector with `debug_config.yaml` which minimizes filtering.
2. **Verify DNS Activity**: Manually trigger DNS lookups by using commands like `nslookup example.com`.
3. **Check ETW Provider**: Verify the provider GUID is correct and the DNS Client ETW provider is active.
4. **Examine Event Stats**: Look for the periodic event statistics logs (added in latest version).
5. **Check Error Logs**: Look for any error messages related to ETW session or consumer.

**Solutions:**

1. **Restart DNS Client Service**: Restart the Windows DNS Client service to ensure it's generating events.
   ```
   net stop "DNS Client"
   net start "DNS Client"
   ```

2. **Check ETW Provider Registration**: Verify the DNS Client ETW provider is registered.
   ```
   logman query providers | findstr DNS
   ```

3. **Run with Minimal Filtering**: Use the debug configuration which minimizes filtering:
   ```
   .\otelcol-contrib.exe --config=.\configs\debug_config.yaml
   ```

4. **Check DNS Client Event Logging**: Enable DNS Client debug logging in the Windows Registry:
   ```
   reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v EnableLogging /t REG_DWORD /d 1 /f
   ```

## Diagnostics Commands

### Check ETW Providers

```
logman query providers
```

### List Active ETW Sessions

```
logman query -ets
```

### Test DNS Client Events

```
nslookup google.com
nslookup microsoft.com
ipconfig /flushdns
nslookup -type=AAAA google.com
```

### Check Event Hub Connectivity

```
Test-NetConnection -ComputerName ehns-ase-defender01-ayfsr.servicebus.windows.net -Port 9093
```

### Validate Permission Level

The collector requires administrative privileges to capture ETW events. Ensure you're running it as Administrator.

## Event Volume Issues

### Too Many Events

**Symptom:** The collector is generating a high volume of events, overwhelming Event Hub or making analysis difficult.

**Solutions:**

1. **Increase Filtering**: Add common operational domains to the `excluded_domains` list.
   ```yaml
   excluded_domains:
     - "*.opinsights.azure.com"
     - "*.guestconfiguration.azure.com"
     - "*.internal.cloudapp.net"
     - "*.windows.com"
     - "*.microsoft.com"
     - "*.msftncsi.com"
     - "wpad.*"
     - "_ldap._tcp.dc._msdcs.*"
   ```

2. **Enable AAAA Filtering**: Enable AAAA record filtering to reduce duplicates.
   ```yaml
   exclude_aaaa_records: true
   ```

3. **Enhance Deduplication**: Reduce the deduplication window.
   ```yaml
   enable_deduplication: true
   deduplication_window: 120  # 2 minutes
   ```

### Missing Security-Relevant Events

**Symptom:** The collector is filtering out security-relevant events.

**Solutions:**

1. **Review Domain Exclusions**: Ensure excluded domains don't include potential threats.
2. **Disable Info Event Filtering**: Consider including Info events if needed.
   ```yaml
   include_info_events: true
   ```
3. **Review Event ID Exclusions**: Verify excluded Event IDs don't contain security relevance.

## Refactored Code Structure Issues

The code has been refactored into a more modular structure to improve maintainability. If you encounter issues with the refactored code:

1. **Import Path Issues**: Ensure all import paths are correct, especially after moving code to different packages.
2. **Missing Dependencies**: Check that all required packages are imported.
3. **Interface Compliance**: Verify that the refactored receiver still implements all required interfaces.

## ETW-Specific Issues

### ETW Session Already Exists

**Symptom:** Error message about session already existing.

**Solution:**
```
logman stop DNSClientTrace -ets
```

### ETW Provider Not Found

**Symptom:** Error about invalid or missing ETW provider.

**Solution:**
Verify provider GUID and registration:
```
logman query providers | findstr DNS
```

## Debugging Techniques

### Enable Console Logging

Add the console exporter to see events in real-time:

```yaml
exporters:
  logging:
    loglevel: debug
    verbosity: detailed

service:
  pipelines:
    logs/dns_client:
      exporters: [kafka, logging]
```

### Debug ETW Events Directly

Use Windows Event Tracing tools to verify events:

```
wevtutil im Microsoft-Windows-DNSClient.man
wevtutil qe Microsoft-Windows-DNSClient/Operational /f:text /c:5
```

### Monitor Event Hub Throughput

Check Azure Portal to verify events reaching Event Hub:
- Navigate to Event Hub namespace
- Check "Overview" for throughput metrics
- Examine "Messages" metrics to verify events are flowing

### Use Event Stats Logging

The refactored code includes periodic event statistics logging. Look for lines like:

```
2025-02-27T15:30:45.123Z info DNS event statistics {"total_received": 1520, "filtered_count": 1350, "passed_filters": 170, "filter_percentage": 88.8}
```

This shows the total events received, how many were filtered, and the filtering percentage.

## Performance Optimization

If performance is an issue:

1. **Increase Batch Size**: 
   ```yaml
   processors:
     batch:
       send_batch_size: 200
   ```

2. **Optimize Deduplication**: 
   - Consider increasing prune threshold
   - Review cache cleaning frequency

3. **Reduce Logging Level** (for production):
   ```yaml
   telemetry:
     logs:
       level: "info"
   ```

## Contact Information

If you continue to encounter issues, contact the development team or open an issue in the repository with:
1. Full logs from a debug run
2. Configuration file used
3. Steps to reproduce the issue
4. Any error messages or unexpected behavior

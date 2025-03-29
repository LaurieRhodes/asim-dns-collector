# ASIM DNS Collector Installation Guide

This guide provides step-by-step instructions for installing and configuring the ASIM DNS Collector on a Windows server. The collector captures DNS Server events via ETW (Event Tracing for Windows) and forwards them to Azure Event Hubs in the Microsoft Sentinel ASIM format.

## Prerequisites

- Windows Server 2016 or later
- DNS Server role installed (if collecting DNS Server events)
- Administrative privileges
- .NET 6.0 Runtime or later (if running as a service)
- Azure Event Hubs namespace and access credentials

## Download and Preparation

1. Download the latest release of the ASIM DNS Collector from the GitHub repository.

2. Create a dedicated directory for the collector:
   ```
   mkdir C:\Program Files\ASIMDNSCollector
   ```

3. Extract the downloaded release package to this directory.

4. Verify the directory contains the following files:
   - `asim-dns-collector.exe` - Main executable
   - `configs` - Directory containing configuration files
   - `LICENSE` - License file
   - `README.md` - Basic documentation

## Configuration

1. Navigate to the `configs` directory and locate the appropriate config file:
   - `dns_server_config.yaml` for DNS Server event collection
   - `config.yaml` for DNS Client event collection

2. Edit the selected configuration file to add your Azure Event Hubs connection details:

   ```yaml
   exporters:
     kafka:
       brokers: ["<Your Event Hub Namespace>.servicebus.windows.net:9093"]
       topic: "asimdnsactivitylogs"
       auth:
         sasl:
           mechanism: PLAIN
           username: $$ConnectionString
           password: Endpoint=sb://<Your Event Hub Namespace>.servicebus.windows.net/;SharedAccessKeyName=<Your Access Key Name>;SharedAccessKey=<Your Access Key>=;EntityPath=<Your Event Hub Name>
   ```

   Replace the placeholders with your actual Event Hub details:
   - `<Your Event Hub Namespace>` - Your Event Hub namespace (e.g., `myeventhubs`)
   - `<Your Access Key Name>` - Shared Access Policy name (e.g., `RootManageSharedAccessKey`)
   - `<Your Access Key>` - The actual access key
   - `<Your Event Hub Name>` - The name of your Event Hub (e.g., `asimdnsactivitylogs`)

3. Adjust filtering options if needed (see `FILTERING_USAGE.md` for details).

## Running Manually (for Testing)

Before setting up the service, it's recommended to test the collector manually:

1. Open an administrative PowerShell or Command Prompt:
   - Right-click on PowerShell/Command Prompt
   - Select "Run as administrator"

2. Navigate to the installation directory:
   ```
   cd "C:\Program Files\ASIMDNSCollector"
   ```

3. Run the collector with the appropriate configuration:
   ```
   .\asim-dns-collector.exe --config=.\configs\dns_server_config.yaml
   ```

4. Verify that events are being collected and no errors are displayed.

5. Press Ctrl+C to stop the collector.

## Installing as a Windows Service

For production use, the collector should be installed as a Windows service:

### Method 1: Using SC Command

1. Open an administrative PowerShell or Command Prompt.

2. Create the service using the `sc` command:
   ```
   sc create ASIMDNSCollector binPath= "\"C:\Program Files\ASIMDNSCollector\asim-dns-collector.exe\" --config=\"C:\Program Files\ASIMDNSCollector\configs\dns_server_config.yaml\"" start= auto
   ```

3. Set the service description:
   ```
   sc description ASIMDNSCollector "ASIM DNS Collector Service for Microsoft Sentinel"
   ```

4. Configure the service to restart on failure:
   ```
   sc failure ASIMDNSCollector reset= 86400 actions= restart/60000/restart/120000/restart/300000
   ```

5. Start the service:
   ```
   sc start ASIMDNSCollector
   ```

### Method 2: Using NSSM (Non-Sucking Service Manager)

NSSM provides more configuration options and easier management:

1. Download NSSM from [nssm.cc](https://nssm.cc/download).

2. Extract the appropriate version (32-bit or 64-bit) of `nssm.exe` to a directory in your PATH or to the ASIMDNSCollector directory.

3. Open an administrative PowerShell or Command Prompt.

4. Run NSSM to create the service:
   ```
   nssm install ASIMDNSCollector
   ```

5. In the NSSM dialog:
   - Path: Browse to `C:\Program Files\ASIMDNSCollector\asim-dns-collector.exe`
   - Startup directory: `C:\Program Files\ASIMDNSCollector`
   - Arguments: `--config=.\configs\dns_server_config.yaml`

6. Go to the "Details" tab:
   - Display name: `ASIM DNS Collector`
   - Description: `ASIM DNS Collector Service for Microsoft Sentinel`
   - Startup type: `Automatic`

7. Go to the "Log on" tab:
   - Select "Local System account"
   - Check "Allow service to interact with desktop" (optional)

8. Go to the "Dependencies" tab:
   - Add `DNS` as a dependency (for DNS Server collection)

9. Go to the "Process" tab:
   - Priority: `Normal`

10. Go to the "Shutdown" tab:
    - Set appropriate timeouts (e.g., 30000 ms)

11. Click "Install service".

12. Start the service:
    ```
    nssm start ASIMDNSCollector
    ```

## Verifying Service Operation

1. Check the service status:
   ```
   sc query ASIMDNSCollector
   ```

2. View Windows Event Logs for any issues:
   - Open Event Viewer
   - Navigate to Windows Logs > Application
   - Look for events with source "ASIMDNSCollector"

3. Check if data is flowing to your Event Hub:
   - Use the Azure Portal to monitor Event Hub metrics
   - Verify incoming messages in Microsoft Sentinel

## Configuring Log Rotation

To manage log files generated by the collector:

1. Create a log directory:
   ```
   mkdir "C:\Program Files\ASIMDNSCollector\logs"
   ```

2. Modify your configuration file to enable file logging:
   ```yaml
   exporters:
     # ... existing exporters ...
     
     file:
       path: "C:\\Program Files\\ASIMDNSCollector\\logs\\dns_events.log"
       rotation:
         max_megabytes: 100
         max_days: 7
         max_backups: 5
   
   service:
     pipelines:
       logs/dns_server:
         exporters: [kafka, file]  # Add file exporter
   ```

3. Set up a scheduled task to clean up old logs if needed.

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the service is running with administrative privileges.
   
2. **ETW Session Already Exists**: If a previous instance crashed, clean up the ETW session:
   ```
   logman stop DNSServerTrace -ets
   ```

3. **No Events Collected**: Verify that:
   - The DNS Server role is installed
   - The correct provider GUID is configured
   - The enable_flags are set correctly
   - The service is running

4. **Connection Failures to Event Hub**: Check:
   - Network connectivity to Event Hub
   - Firewall rules (port 9093 must be open)
   - Connection string and access credentials

### Getting Help

If you encounter issues not covered in this guide:

1. Check the project documentation in the `docs` directory.
2. Look for error messages in Event Viewer and the console output.
3. Enable debug logging by setting the telemetry level to `debug` in the configuration.
4. File an issue on the GitHub repository with detailed error information.

## Updating the Collector

To update the collector to a newer version:

1. Stop the service:
   ```
   sc stop ASIMDNSCollector
   ```

2. Backup your configuration files.

3. Replace the executable and supporting files with the new version.

4. Update the configuration files if required by the new version.

5. Start the service:
   ```
   sc start ASIMDNSCollector
   ```

## Security Considerations

1. **Least Privilege**: While the collector requires administrative privileges to access ETW, consider using a dedicated service account with minimum required permissions.

2. **Secure Configuration**: Protect the configuration files containing Event Hub credentials.

3. **Network Security**: Ensure network traffic to Azure Event Hubs is secured (TLS is enabled by default).

4. **Auditing**: Enable auditing on the collector directory and executable to monitor changes.

## Conclusion

The ASIM DNS Collector should now be installed and running as a Windows service, collecting DNS Server or Client events and forwarding them to Microsoft Sentinel in the ASIM format. Monitor the service periodically to ensure continued operation and adjust filtering settings as needed to optimize the signal-to-noise ratio.

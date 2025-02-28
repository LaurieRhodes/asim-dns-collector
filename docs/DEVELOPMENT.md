# Development Guide

## Development Environment Setup

### Prerequisites

- Go 1.21+
- OpenTelemetry Collector Builder
- Git

### Windows-Specific Requirements

- Windows 10/11 or Windows Server 2016+
- Administrator privileges (for ETW session creation)

### Installing Dependencies

1. Install Go:
   
   ```
   https://golang.org/dl/
   ```

2. Install OpenTelemetry Collector Builder:
   
   ```bash
   go install go.opentelemetry.io/collector/cmd/builder@v0.89.0
   ```

3. Clone the repository:
   
   ```bash
   git clone https://github.com/LaurieRhodes/asim-dns-collector.git
   cd asim-dns-collector
   ```

## Building the Collector

### Development Build

```bash
builder --config builder-config.yaml
```

This will generate the collector executable in the `./bin` directory.

### Production Build

For a production build with optimized performance:

```bash
builder --config builder-config.yaml --skip-compilation
cd bin
go build -ldflags="-s -w" -o asim-dns-collector-prod.exe
```

## Testing

### Running Unit Tests

```bash
cd internal/receiver/asimdns
go test -v
```

### Testing the Collector

Run the collector with a test configuration:

```bash
cd bin
./asim-dns-collector --config=../configs/config.yaml
```

### Viewing Debug Information

The collector includes the zpages extension, which provides diagnostic information:

1. Start the collector
2. Open your web browser and navigate to: http://localhost:55679

## Project Structure

- `builder-config.yaml`: Configuration for the OpenTelemetry Collector Builder
- `cmd/`: Main application entry point
- `configs/`: Example configuration files
- `docs/`: Documentation
- `internal/`: Internal package code
  - `internal/receiver/asimdns/`: ASIM DNS receiver implementation
    - `asimdns.go`: Main receiver code (platform-independent)
    - `asimdns_windows.go`: Windows-specific ETW implementation
    - `asimdns_test.go`: Unit tests

## Development Workflow

### Adding Features

1. Create a feature branch
2. Implement the feature
3. Add tests
4. Submit a pull request

### Code Style Guidelines

- Follow standard Go formatting with `gofmt`
- Use meaningful variable and function names
- Add comments for public functions and complex logic
- Keep functions short and focused

## ETW Development Tips

### Viewing Available ETW Providers

Use the Windows Event Viewer to explore available ETW providers:

1. Open Event Viewer
2. Click on "View" → "Show Analytic and Debug Logs"
3. Navigate to "Applications and Services Logs" → "Microsoft" → "Windows" → "DNS-Client"

### Capturing ETW Events Manually

Use the Windows Performance Recorder (WPR) to capture ETW events for analysis:

1. Open Windows Performance Recorder
2. Add "DNS" to the selected profiles
3. Click "Start" to begin recording
4. Perform the actions you want to capture
5. Click "Save" to save the trace file
6. Open with Windows Performance Analyzer

### Common ETW Issues

1. **Access Denied Error**:
   
   - Ensure the application is running with administrator privileges
   - Check that no other application is using the same session name

2. **No Events Received**:
   
   - Verify the provider GUID is correct
   - Ensure the event keywords and level are appropriate
   - Check that DNS activity is occurring on the system

3. **Performance Issues**:
   
   - Adjust buffer settings (buffer_size, min_buffers, max_buffers)
   - Implement more targeted event filtering
   - Process events asynchronously

## Debugging Resources

- [ETW Explorer](https://github.com/zodiacon/EtwExplorer): Tool for exploring ETW providers
- [Windows Performance Analyzer](https://docs.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer): Analysis tool for ETW traces
- [Message Analyzer](https://docs.microsoft.com/en-us/message-analyzer/microsoft-message-analyzer-operating-guide): Advanced tool for tracing and network analysis

## Common Tasks

### Adding a New ETW Provider

1. Identify the provider GUID and name
2. Update the configuration to include the new provider
3. Modify the event parsing logic to handle the new event types

### Modifying Event Transformation

Update the `convertEventToLogs` function in `asimdns_windows.go` to modify how events are transformed to OpenTelemetry logs.

### Adding Custom Filters

Implement custom filtering logic in the event callback to filter events based on specific criteria.

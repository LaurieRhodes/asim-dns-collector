package asimdns

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
)

// Config defines configuration for the ASIM DNS receiver
type Config struct {
	// SessionName is the name of the ETW tracing session
	SessionName string `mapstructure:"session_name"`

	// ProviderGUID is the ETW provider GUID for DNS events
	ProviderGUID string `mapstructure:"provider_guid"`

	// EnableFlags are the ETW keyword flags for event filtering
	EnableFlags uint64 `mapstructure:"enable_flags"`

	// EnableLevel sets the verbosity level of event tracing
	EnableLevel int `mapstructure:"enable_level"`

	// Event type filtering
	IncludeInfoEvents bool     `mapstructure:"include_info_events"`
	ExcludedEventIDs  []uint16 `mapstructure:"excluded_event_ids"`
	
	// Domain filtering
	ExcludedDomains []string `mapstructure:"excluded_domains"`
	
	// Query deduplication
	EnableDeduplication  bool `mapstructure:"enable_deduplication"`
	DeduplicationWindow  int  `mapstructure:"deduplication_window"`
	
	// Query type filtering
	ExcludeAAAARecords bool `mapstructure:"exclude_aaaa_records"`
}

// Provider GUID constants
const (
	DNSClientProviderGUID = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
	DNSServerProviderGUID = "{EB79061A-A566-4698-9119-3ED2807060E7}"
)

// Validate checks the configuration and sets default values
func (cfg *Config) Validate() error {
	// Validate ProviderGUID
	if cfg.ProviderGUID == "" {
		return fmt.Errorf("provider_guid must be specified")
	}

	// Set default values if not provided
	if cfg.SessionName == "" {
		// Set session name based on provider type
		if cfg.ProviderGUID == DNSServerProviderGUID {
			cfg.SessionName = "ASIMDNSServerTrace"
		} else {
			cfg.SessionName = "ASIMDNSClientTrace"
		}
	}

	// Set default EnableFlags based on provider type
	if cfg.EnableFlags == 0 {
		if cfg.ProviderGUID == DNSServerProviderGUID {
			// For DNS Server, enable flags for query-related events by default
			// This includes query received, response success/failure, and recursion events
			cfg.EnableFlags = 0x000000000000003F // Combined flags for query-related events
		} else {
			// For DNS Client, enable all events by default
			cfg.EnableFlags = 0x8000000000000FFF // All DNS Client events
		}
	}

	if cfg.EnableLevel == 0 {
		if cfg.ProviderGUID == DNSServerProviderGUID {
			cfg.EnableLevel = 4 // Information level for DNS Server
		} else {
			cfg.EnableLevel = 5 // Verbose for DNS Client
		}
	}

	// Set filtering defaults based on provider type
	if cfg.ProviderGUID == DNSServerProviderGUID {
		// For DNS Server, include info events by default
		if !cfg.IncludeInfoEvents && len(cfg.ExcludedEventIDs) == 0 {
			cfg.IncludeInfoEvents = true
			cfg.ExcludedEventIDs = []uint16{} // No default exclusions
		}
	} else {
		// For DNS Client, exclude info events by default
		if !cfg.IncludeInfoEvents && len(cfg.ExcludedEventIDs) == 0 {
			cfg.ExcludedEventIDs = []uint16{1001, 1015, 1016, 1019}
		}
	}

	// Set default deduplication window if enabled but not configured
	if cfg.EnableDeduplication && cfg.DeduplicationWindow == 0 {
		cfg.DeduplicationWindow = 300 // 5 minutes in seconds
	}

	return nil
}

// Unmarshal provides custom unmarshaling logic
func (cfg *Config) Unmarshal(conf *confmap.Conf) error {
	// Default implementation, can be expanded if needed
	return conf.Unmarshal(cfg)
}

// Ensure Config implements component.Config interface
var _ component.Config = (*Config)(nil)

// EventRecord represents an ETW event
type EventRecord struct {
	ProviderGUID string
	EventID      uint16
	EventData    map[string]interface{}
	Timestamp    time.Time
	ProcessID    uint32
}

// DNSReceiver implements receiver.Logs for non-Windows platforms or when ETW is disabled
// This is a stub implementation that simulates events
type DNSReceiver struct {
	logger     *zap.Logger
	config     *Config
	consumer   consumer.Logs
	eventChan  chan *EventRecord
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
}

const (
	typeStr = "asimdns"
)

// NewFactory creates a factory for ASIM DNS receiver
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		typeStr,
		createDefaultConfig,
		receiver.WithLogs(createLogsReceiver, component.StabilityLevelAlpha))
}

// createDefaultConfig creates default configuration for the receiver
func createDefaultConfig() component.Config {
	return &Config{
		SessionName:  "ASIMDNSClientTrace", // Default to client trace
		ProviderGUID: DNSClientProviderGUID, // Default to DNS Client provider
		EnableFlags:  0x8000000000000FFF,    // All DNS Client events
		EnableLevel:  5,                      // Verbose level
		// Default filtering settings
		IncludeInfoEvents:    false,
		ExcludedEventIDs:     []uint16{1001, 1015, 1016, 1019},
		ExcludedDomains:      []string{},
		EnableDeduplication:  true,
		DeduplicationWindow:  300, // 5 minutes in seconds
		ExcludeAAAARecords:   false,
	}
}

// createLogsReceiver creates a logs receiver based on provided configuration.
func createLogsReceiver(
	_ context.Context,
	params receiver.CreateSettings,
	cfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	rCfg, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid configuration: %v", cfg)
	}

	// On Windows, use the ETW-based receiver
	if runtime.GOOS == "windows" {
		return newDNSEtwReceiver(params, rCfg, consumer)
	}

	// On non-Windows platforms, use the stub receiver
	return &DNSReceiver{
		logger:    params.Logger,
		config:    rCfg,
		consumer:  consumer,
		eventChan: make(chan *EventRecord, 1000),
	}, nil
}

// Start implements receiver.Logs for non-Windows platforms
func (r *DNSReceiver) Start(ctx context.Context, host component.Host) error {
	ctx, cancel := context.WithCancel(ctx)
	r.cancelFunc = cancel

	// Determine provider type for logging
	providerType := "DNS Client"
	if r.config.ProviderGUID == DNSServerProviderGUID {
		providerType = "DNS Server"
	}

	// Simulate ETW session start - will be replaced with actual ETW implementation later
	r.logger.Info("Starting ASIM DNS receiver (stub implementation)",
		zap.String("provider_type", providerType),
		zap.String("provider_guid", r.config.ProviderGUID),
		zap.Int("level", r.config.EnableLevel),
		zap.Uint64("keywords", r.config.EnableFlags))

	// Start processing events (simulated for now)
	r.wg.Add(1)
	go r.simulateEvents(ctx)

	return nil
}

// Shutdown implements receiver.Logs for non-Windows platforms
func (r *DNSReceiver) Shutdown(ctx context.Context) error {
	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	
	// Wait for event processing to complete
	r.wg.Wait()

	r.logger.Info("ASIM DNS receiver shutdown complete")
	return nil
}

// simulateEvents simulates ETW DNS events for demonstration
func (r *DNSReceiver) simulateEvents(ctx context.Context) {
	defer r.wg.Done()
	
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Create simulated event based on provider type
			var event *EventRecord
			
			if r.config.ProviderGUID == DNSServerProviderGUID {
				// Simulate DNS Server query event
				event = &EventRecord{
					ProviderGUID: r.config.ProviderGUID,
					EventID:      256, // DNS Server Query event
					Timestamp:    time.Now(),
					ProcessID:    4, // DNS Server process
					EventData: map[string]interface{}{
						"QNAME": "example.com",
						"QTYPE": "1", // A record
					},
				}
			} else {
				// Simulate DNS Client query event
				event = &EventRecord{
					ProviderGUID: r.config.ProviderGUID,
					EventID:      3006, // DNS Client Query event
					Timestamp:    time.Now(),
					ProcessID:    1234, // Client process
					EventData: map[string]interface{}{
						"QueryName": "example.com",
						"QueryType": "1", // A record
					},
				}
			}
			
			logs := r.convertEventToLogs(event)
			
			// Check if logs have any records before sending
			if logs.ResourceLogs().Len() > 0 && 
               logs.ResourceLogs().At(0).ScopeLogs().Len() > 0 && 
               logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len() > 0 {
				if err := r.consumer.ConsumeLogs(ctx, logs); err != nil {
					r.logger.Error("Failed to consume logs", zap.Error(err))
				}
			}
		}
	}
}

// convertEventToLogs converts ETW DNS events to OpenTelemetry logs
func (r *DNSReceiver) convertEventToLogs(event *EventRecord) plog.Logs {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	
	// Set resource attributes based on provider type
	serviceName := "windows_dns_client"
	if event.ProviderGUID == DNSServerProviderGUID {
		serviceName = "windows_dns_server"
	}
	
	resourceLogs.Resource().Attributes().PutStr("service.name", serviceName)
	resourceLogs.Resource().Attributes().PutStr("service.namespace", "asim_dns")
	
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	scopeLogs.Scope().SetName("asim.dns.events")
	
	logRecord := scopeLogs.LogRecords().AppendEmpty()
	
	// Set timestamp
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(event.Timestamp))
	
	// Set basic event info based on provider type
	if event.ProviderGUID == DNSServerProviderGUID {
		logRecord.Body().SetStr(fmt.Sprintf("DNS Server Event: %d", event.EventID))
		logRecord.Attributes().PutStr("EventProduct", "DNS Server")
	} else {
		logRecord.Body().SetStr(fmt.Sprintf("DNS Client Event: %d", event.EventID))
		logRecord.Attributes().PutStr("EventProduct", "DNS Client")
	}
	
	logRecord.Attributes().PutStr("EventVendor", "Microsoft")
	logRecord.Attributes().PutStr("provider.guid", event.ProviderGUID)
	logRecord.Attributes().PutInt("event.id", int64(event.EventID))
	logRecord.Attributes().PutInt("process.pid", int64(event.ProcessID))
	
	// Add event-specific data if available
	if event.EventData != nil {
		for key, value := range event.EventData {
			if strValue, ok := value.(string); ok {
				logRecord.Attributes().PutStr("dns."+key, strValue)
			} else if intValue, ok := value.(int64); ok {
				logRecord.Attributes().PutInt("dns."+key, intValue)
			}
		}
	}
	
	return logs
}
//go:build windows
// +build windows

package asimdns

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"

	"github.com/LaurieRhodes/asim-dns-collector/internal/receiver/asimdns/filtering"
)

// DNSEtwReceiver is the Windows-specific implementation using golang-etw
type DNSEtwReceiver struct {
	logger         *zap.Logger
	config         *Config
	consumer       consumer.Logs
	session        *etw.RealTimeSession
	etwConsumer    *etw.Consumer
	wg             sync.WaitGroup
	cancelFunc     context.CancelFunc
	filterManager  *filtering.FilterManager
}

// Start implements receiver.Logs for Windows
func (r *DNSEtwReceiver) Start(ctx context.Context, host component.Host) error {
	ctx, cancel := context.WithCancel(ctx)
	r.cancelFunc = cancel

	// Create ETW session
	r.session = etw.NewRealTimeSession(r.config.SessionName)

	// Parse provider GUID and enable it in the session
	provider, err := etw.ParseProvider(r.config.ProviderGUID)
	if err != nil {
		return fmt.Errorf("failed to parse provider GUID: %w", err)
	}

	// Set provider parameters from config
	provider.EnableLevel = uint8(r.config.EnableLevel)
	provider.MatchAnyKeyword = r.config.EnableFlags

	// Start session and enable provider
	if err := r.session.Start(); err != nil {
		return fmt.Errorf("failed to start ETW session: %w", err)
	}

	// Enable provider to collect events
	if err := r.session.EnableProvider(provider); err != nil {
		return fmt.Errorf("failed to enable provider: %w", err)
	}

	// Create ETW consumer
	r.etwConsumer = etw.NewRealTimeConsumer(ctx)
	r.etwConsumer.FromSessions(r.session)

	// Start periodic logger to monitor event processing
	go r.logEventStats(ctx)

	// Set up the event callback to process events
	r.etwConsumer.EventCallback = func(event *etw.Event) error {
		// Skip this event if the context is done
		if ctx.Err() != nil {
			return nil
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
		return nil
	}

	// Start consumer in a separate goroutine
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.logger.Info("Starting ETW consumer")
		if err := r.etwConsumer.Start(); err != nil {
			r.logger.Error("ETW consumer error", zap.Error(err))
		}
		r.logger.Info("ETW consumer exited")
	}()

	r.logger.Info("ASIM DNS ETW receiver started",
		zap.String("provider", r.config.ProviderGUID),
		zap.Int("level", r.config.EnableLevel),
		zap.Uint64("keywords", r.config.EnableFlags),
		zap.Bool("filtering_enabled", !r.config.IncludeInfoEvents || 
			len(r.config.ExcludedEventIDs) > 0 || 
			len(r.config.ExcludedDomains) > 0 || 
			r.config.EnableDeduplication))

	return nil
}

// logEventStats logs event processing statistics periodically
func (r *DNSEtwReceiver) logEventStats(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			totalEvents := r.filterManager.GetTotalEvents()
			filteredEvents := r.filterManager.GetFilteredEvents()
			filterPercentage := r.filterManager.GetFilterPercentage()
			
			r.logger.Info("DNS event statistics", 
				zap.Int64("total_received", totalEvents),
				zap.Int64("filtered_count", filteredEvents),
				zap.Int64("passed_filters", totalEvents - filteredEvents),
				zap.Float64("filter_percentage", filterPercentage))
		}
	}
}

// Shutdown implements receiver.Logs for Windows
func (r *DNSEtwReceiver) Shutdown(ctx context.Context) error {
	r.logger.Info("Shutting down ASIM DNS ETW receiver")
	
	if r.cancelFunc != nil {
		r.cancelFunc()
	}

	// Stop the ETW consumer
	if r.etwConsumer != nil {
		r.logger.Info("Stopping ETW consumer")
		if err := r.etwConsumer.Stop(); err != nil {
			r.logger.Warn("Error stopping ETW consumer", zap.Error(err))
		}
	}

	// Stop the ETW session
	if r.session != nil {
		r.logger.Info("Stopping ETW session")
		if err := r.session.Stop(); err != nil {
			r.logger.Warn("Error stopping ETW session", zap.Error(err))
		}
	}

	// Wait for event processing to complete
	r.wg.Wait()
	
	// Log final statistics
	totalEvents := r.filterManager.GetTotalEvents()
	filteredEvents := r.filterManager.GetFilteredEvents()
	
	r.logger.Info("Final DNS event statistics",
		zap.Int64("total_events", totalEvents),
		zap.Int64("filtered_events", filteredEvents))

	r.logger.Info("ASIM DNS ETW receiver shutdown complete")
	return nil
}

// convertEventToLogs converts ETW events to OpenTelemetry logs with ASIM DNS schema
func (r *DNSEtwReceiver) convertEventToLogs(event *etw.Event) plog.Logs {
	// Apply filtering via filter manager
	if r.filterManager.ShouldFilter(event) {
		return plog.NewLogs()
	}
	
	// If we reach here, the event should be processed
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	
	// Set resource attributes
	resourceLogs.Resource().Attributes().PutStr("service.name", "windows_dns_client")
	resourceLogs.Resource().Attributes().PutStr("service.namespace", "asim_dns")
	
	// Create scope logs
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	scopeLogs.Scope().SetName("asim.dns.events")
	
	// Create log record
	logRecord := scopeLogs.LogRecords().AppendEmpty()
	
	// Set timestamp from ETW event
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(event.System.TimeCreated.SystemTime))
	
	// Determine ASIM event type and subtype
	eventType, eventSubType := getAsimEventType(event.System.EventID)
	
	// Set body for context
	logRecord.Body().SetStr(fmt.Sprintf("DNS Client Event: %s %s (ID: %d)", 
		eventType, eventSubType, event.System.EventID))
	
	// Set common ASIM fields
	logRecord.Attributes().PutStr("EventType", eventType)
	logRecord.Attributes().PutStr("EventSubType", eventSubType)
	logRecord.Attributes().PutInt("EventCount", 1)
	logRecord.Attributes().PutStr("EventProduct", "DNS Client")
	logRecord.Attributes().PutStr("EventVendor", "Microsoft")
	logRecord.Attributes().PutStr("EventOriginalType", fmt.Sprintf("%d", event.System.EventID))
	
	// Set device information fields
	setDeviceFields(logRecord)
	
	// Set DNS query fields
	if queryName, ok := getEventDataString(event, "QueryName"); ok {
		logRecord.Attributes().PutStr("DnsQuery", queryName)
	}
	
	// Set DNS query type and name
	if queryTypeStr, ok := getEventDataString(event, "QueryType"); ok {
		if queryTypeInt, err := strconv.Atoi(queryTypeStr); err == nil {
			logRecord.Attributes().PutInt("DnsQueryType", int64(queryTypeInt))
			logRecord.Attributes().PutStr("DnsQueryTypeName", getDnsQueryTypeName(queryTypeInt))
		}
	}
	
	// Set network fields
	setNetworkFields(event, logRecord)
	
	// Add DNS flags if available
	if queryOptions, ok := getEventDataString(event, "QueryOptions"); ok {
		if optionsInt, err := strconv.ParseUint(queryOptions, 10, 64); err == nil {
			setDnsFlags(optionsInt, logRecord)
		}
	}
	
	// Set DNS session ID
	sessionID := fmt.Sprintf("%d-%d-%d", 
		event.System.Execution.ProcessID, 
		event.System.EventID, 
		event.System.TimeCreated.SystemTime.UnixNano())
	logRecord.Attributes().PutStr("DnsSessionId", sessionID)
	
	// Handle event result based on event type
	if eventType == "Query" && eventSubType == "response" {
		setResponseFields(event, logRecord)
	} else {
		// For non-response events (requests, cache operations)
		logRecord.Attributes().PutStr("EventResult", "NA")
		logRecord.Attributes().PutStr("EventResultDetails", "NA")
	}
	
	// Add any remaining fields as additional fields
	setAdditionalFields(event, logRecord)
	
	// Log the transformation for debugging - safely check for DnsQuery
	dnsQuery := "not_set"
	if val, ok := logRecord.Attributes().Get("DnsQuery"); ok {
		dnsQuery = val.Str()
	}
	
	// Debug log occasionally for processed events
	if r.filterManager.GetTotalEvents() % 100 == 0 {
		r.logger.Debug("Applied ASIM transformation", 
			zap.String("EventType", eventType),
			zap.String("EventSubType", eventSubType),
			zap.String("DnsQuery", dnsQuery))
	}
	
	return logs
}

// newDNSEtwReceiver creates a new Windows-specific ETW receiver
func newDNSEtwReceiver(
	settings receiver.CreateSettings,
	cfg *Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	// Create the filter manager
	filterManager := filtering.NewFilterManager(
		settings.Logger,
		cfg.IncludeInfoEvents,
		cfg.ExcludedEventIDs,
		cfg.ExcludedDomains,
		cfg.ExcludeAAAARecords,
		cfg.EnableDeduplication,
		cfg.DeduplicationWindow,
		getEventDataString,
		getAsimEventType,
	)
	
	r := &DNSEtwReceiver{
		logger:        settings.Logger,
		config:        cfg,
		consumer:      consumer,
		filterManager: filterManager,
	}
	
	settings.Logger.Info("DNS receiver configured with filtering",
		zap.Bool("include_info_events", cfg.IncludeInfoEvents),
		zap.Int("excluded_event_ids_count", len(cfg.ExcludedEventIDs)),
		zap.Int("excluded_domains_count", len(cfg.ExcludedDomains)),
		zap.Bool("deduplication_enabled", cfg.EnableDeduplication),
		zap.Int("deduplication_window", cfg.DeduplicationWindow),
		zap.Bool("exclude_aaaa_records", cfg.ExcludeAAAARecords))
	
	return r, nil
}

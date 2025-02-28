package asimdns

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"
)

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	if cfg == nil {
		t.Fatalf("failed to create default config")
	}
	if cfg.Type() != typeStr {
		t.Fatalf("factory should create config with type %q, got %q", typeStr, cfg.Type())
	}
}

func TestCreateLogsReceiver(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	params := receivertest.NewNopCreateSettings()
	mockConsumer := consumertest.NewNop()

	receiver, err := factory.CreateLogsReceiver(context.Background(), params, cfg, mockConsumer)
	if err != nil {
		t.Fatalf("failed to create logs receiver: %v", err)
	}
	if receiver == nil {
		t.Fatal("failed to create logs receiver")
	}
}

func TestStartShutdown(t *testing.T) {
	// Create a logger for testing
	logger, _ := zap.NewDevelopment()

	// Create a DNS receiver
	receiver := &DNSReceiver{
		logger: logger,
		config: &Config{
			SessionName:  "TestSession",
			ProviderGUID: "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}",
			EnableFlags:  0x8000000000000FFF,
			EnableLevel:  5,
		},
		consumer:  consumertest.NewNop(),
		eventChan: make(chan *EventRecord, 10),
	}

	// Test Start
	err := receiver.Start(context.Background(), componenttest.NewNopHost())
	if err != nil {
		t.Fatalf("Failed to start receiver: %v", err)
	}

	// Give it a moment to initialize
	time.Sleep(100 * time.Millisecond)

	// Test Shutdown
	err = receiver.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("Failed to shutdown receiver: %v", err)
	}
}
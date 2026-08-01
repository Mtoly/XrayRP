package panel_test

import (
	"testing"

	"github.com/Mtoly/XrayRP/panel"
)

func TestPanelReadOnlyAccessorsSupportZeroValue(t *testing.T) {
	var runtimePanel panel.Panel

	if runtimePanel.IsRunning() {
		t.Fatal("IsRunning() = true for zero-value Panel")
	}
	if server := runtimePanel.ServerInstance(); server != nil {
		t.Fatalf("ServerInstance() = %p for zero-value Panel, want nil", server)
	}
	if services := runtimePanel.ServicesSnapshot(); len(services) != 0 {
		t.Fatalf("ServicesSnapshot() length = %d for zero-value Panel, want 0", len(services))
	}
}

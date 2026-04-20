package cmd

import "testing"

func TestValidateOpenShiftFlowRejectsUnknownValue(t *testing.T) {
	oldFlow := openshiftFlow
	oldAuthHost := openshiftAuthHost
	defer func() {
		openshiftFlow = oldFlow
		openshiftAuthHost = oldAuthHost
	}()

	openshiftFlow = "unknown"
	openshiftAuthHost = defaultAuthHostname

	if err := validateOpenShiftFlow(); err == nil {
		t.Fatal("expected error for invalid flow")
	}
}

func TestValidateOpenShiftFlowRejectsCustomAuthHostForDeviceExchange(t *testing.T) {
	oldFlow := openshiftFlow
	oldAuthHost := openshiftAuthHost
	defer func() {
		openshiftFlow = oldFlow
		openshiftAuthHost = oldAuthHost
	}()

	openshiftFlow = openShiftFlowDeviceExchange
	openshiftAuthHost = "custom-auth.example"

	if err := validateOpenShiftFlow(); err == nil {
		t.Fatal("expected error for custom auth host with device-exchange flow")
	}
}

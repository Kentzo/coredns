package dso

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestParseTCPPort(t *testing.T) {
	for _, test := range []struct {
		config   string
		expected int
		failing  bool
	}{
		{"dso {\ntcp_port\n}", 0, true},
		{"dso {\ntcp_port 1 2\n}", 0, true},
		{"dso {\ntcp_port -2\n}", 0, true},
		{"dso {\ntcp_port 65536\n}", 0, true},
		{"dso {\ntcp_port -1\n}", -1, false},
		{"dso {\ntcp_port 65535\n}", 65535, false},
	} {
		t.Run(test.config, func(t *testing.T) {
			c := caddy.NewTestController("dns", test.config)
			rawCfg, err := parseConfig(c)
			switch {
			case test.failing && err == nil:
				t.Fatal("Expected error, got nothing")
			case !test.failing && err != nil:
				t.Fatalf("Expected no error, got %v", err)
			case err == nil:
				if *rawCfg.TCPPort != test.expected {
					t.Errorf("Expected %d, got %d", test.expected, *rawCfg.TCPPort)
				}
			}
		})
	}
}

func AssertParseConfig(t *testing.T, input string) rawConfig {
	t.Helper()

	c := caddy.NewTestController("dns", input)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("Failed to parse config %q: %v", input, err)
	}
	return cfg
}

func TestResolveTCPPort(t *testing.T) {
	t.Run("Mismatch", func(t *testing.T) {
		rawCfg := [...]rawConfig{
			AssertParseConfig(t, "dso {\ntcp_port 42\n}"),
			AssertParseConfig(t, "dso {\ntcp_port 9000\n}"),
			AssertParseConfig(t, "dso {\n}"),
		}
		_, err := resolveConfig(rawCfg[:])
		if err == nil {
			t.Error("Expected error, got nothing")
		}
	})
	t.Run("Match", func(t *testing.T) {
		rawCfg := [...]rawConfig{
			AssertParseConfig(t, "dso {\ntcp_port 42\n}"),
			AssertParseConfig(t, "dso {\ntcp_port 42\n}"),
			AssertParseConfig(t, "dso {\n}"),
		}
		cfg, err := resolveConfig(rawCfg[:])
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if cfg.TCPPort != 42 {
			t.Errorf("Expected 42, got %d", cfg.TCPPort)
		}
	})
}

func TestParseTLSPort(t *testing.T) {
	for _, test := range []struct {
		config   string
		expected int
		failing  bool
	}{
		{"dso {\ntls_port\n}", 0, true},
		{"dso {\ntls_port 1 2\n}", 0, true},
		{"dso {\ntls_port -2\n}", 0, true},
		{"dso {\ntls_port 65536\n}", 0, true},
		{"dso {\ntls_port -1\n}", -1, false},
		{"dso {\ntls_port 65535\n}", 65535, false},
	} {
		t.Run(test.config, func(t *testing.T) {
			c := caddy.NewTestController("dns", test.config)
			rawCfg, err := parseConfig(c)
			switch {
			case test.failing && err == nil:
				t.Fatal("Expected error, got nothing")
			case !test.failing && err != nil:
				t.Fatalf("Expected no error, got %v", err)
			case err == nil:
				if *rawCfg.TLSPort != test.expected {
					t.Errorf("Expected %d, got %d", test.expected, *rawCfg.TLSPort)
				}
			}
		})
	}
}

// func TestParsePushClassAny(t *testing.T) {
// 	for _, test := range []struct {
// 		config   string
// 		expected uint16
// 		failing  bool
// 	}{
// 		{"dso {\npush {\nclass_any\n}\n}", 0, true},
// 		{"dso {\npush {\nclass_any FOO\n}\n}", 0, true},
// 		{"dso {\npush {\nclass_any\n}\n}", 0, false},
// 	} {
// 		t.Run(test.config, func(t *testing.T) {
// 			c := caddy.NewTestController("dns", test.config)
// 			rawCfg, err := parseConfig(c)
// 			switch {
// 			case test.failing && err == nil:
// 				t.Fatal("Expected error, got nothing")
// 			case !test.failing && err != nil:
// 				t.Fatalf("Expected no error, got %v", err)
// 			case err == nil:
// 				if *rawCfg.TLSPort != test.expected {
// 					t.Errorf("Expected %d, got %d", test.expected, *rawCfg.TLSPort)
// 				}
// 			}
// 		})
// 	}
// }

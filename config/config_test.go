package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestPluginsUnmarshalFromYAML(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(`
linter:
  plugins:
    - name: subjectcn
      command: ./subjectcn
      args: ["--verbose"]
      dir: /plugins
      numProcesses: 2
      readySignal: true
      artifacts: [certificate, crl]
      version: 1.0.0
      url: https://example.com/subjectcn
    - name: minimal
      command: /plugins/minimal
    - name: disabled
      command: /plugins/disabled
      numProcesses: 0
`)); err != nil {
		t.Fatalf("reading YAML: %v", err)
	}

	var c config
	if err := v.Unmarshal(&c); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}

	two, zero := 2, 0
	want := []PluginConfig{
		{
			Name:         "subjectcn",
			Command:      "./subjectcn",
			Args:         []string{"--verbose"},
			Dir:          "/plugins",
			NumProcesses: &two,
			ReadySignal:  true,
			Artifacts:    []string{"certificate", "crl"},
			Version:      "1.0.0",
			Url:          "https://example.com/subjectcn",
		},
		{Name: "minimal", Command: "/plugins/minimal"},
		{Name: "disabled", Command: "/plugins/disabled", NumProcesses: &zero},
	}
	if !reflect.DeepEqual(c.Linter.Plugins, want) {
		t.Errorf("got %+v\nwant %+v", c.Linter.Plugins, want)
	}
}

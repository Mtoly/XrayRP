package panel

import (
	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service/controller"
)

type Config struct {
	LogConfig          *LogConfig        `mapstructure:"Log"`
	DnsConfigPath      string            `mapstructure:"DnsConfigPath"`
	InboundConfigPath  string            `mapstructure:"InboundConfigPath"`
	OutboundConfigPath string            `mapstructure:"OutboundConfigPath"`
	RouteConfigPath    string            `mapstructure:"RouteConfigPath"`
	ConnectionConfig   *ConnectionConfig `mapstructure:"ConnectionConfig"`
	MachineConfig      *MachineConfig    `mapstructure:"MachineConfig"`
	NodesConfig        []*NodesConfig    `mapstructure:"Nodes"`
}

type MachineConfig struct {
	Enable    bool   `mapstructure:"Enable"`
	PanelType string `mapstructure:"PanelType"`
	ApiHost   string `mapstructure:"ApiHost"`
	MachineID int    `mapstructure:"MachineID"`
	Token     string `mapstructure:"Token"`
	Timeout   int    `mapstructure:"Timeout"`
}

type NodesConfig struct {
	PanelType        string             `mapstructure:"PanelType"`
	ApiConfig        *api.Config        `mapstructure:"ApiConfig"`
	ControllerConfig *controller.Config `mapstructure:"ControllerConfig"`
}

type LogConfig struct {
	Level      string `mapstructure:"Level"`
	AccessPath string `mapstructure:"AccessPath"`
	ErrorPath  string `mapstructure:"ErrorPath"`
}

type ConnectionConfig struct {
	Handshake    uint32 `mapstructure:"handshake"`
	ConnIdle     uint32 `mapstructure:"connIdle"`
	UplinkOnly   uint32 `mapstructure:"uplinkOnly"`
	DownlinkOnly uint32 `mapstructure:"downlinkOnly"`
	BufferSize   int32  `mapstructure:"bufferSize"`
}

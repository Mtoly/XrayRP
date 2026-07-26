package managednode

import (
	"fmt"
	"strconv"
	"strings"
)

// BuildTag constructs the canonical runtime tag while preserving unknown
// protocol names for compatibility.
func BuildTag(protocol, listenIP string, port uint32, nodeID int) string {
	if canonical, ok := canonicalProtocol(protocol); ok {
		protocol = canonical
	}
	return fmt.Sprintf("%s_%s_%d_%d", protocol, listenIP, port, nodeID)
}

// IsTag reports whether tag is a canonical tag for a managed protocol.
func IsTag(tag string) bool {
	parts := strings.Split(tag, "_")
	canonical, managed := canonicalProtocol(parts[0])
	if len(parts) != 4 || !managed || canonical != parts[0] || parts[1] == "" {
		return false
	}

	port, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil || port == 0 || port > 65535 || strconv.FormatUint(port, 10) != parts[2] {
		return false
	}

	nodeID, err := strconv.Atoi(parts[3])
	return err == nil && strconv.Itoa(nodeID) == parts[3]
}

func canonicalProtocol(protocol string) (string, bool) {
	switch strings.ToLower(protocol) {
	case "vless":
		return "VLESS", true
	case "trojan":
		return "Trojan", true
	case "vmess", "v2ray":
		return "Vmess", true
	case "shadowsocks":
		return "Shadowsocks", true
	case "socks":
		return "Socks", true
	case "http":
		return "HTTP", true
	default:
		return "", false
	}
}

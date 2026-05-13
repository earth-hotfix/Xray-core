package convert

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseSubscriptionLinks_Base64(t *testing.T) {
	raw := "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=IGsSxC0wgn7wLy0NM0QN_yOREDKT_814Y_3_rbgDoTc&sid=c8c0f951#node-1\n" +
		"hysteria2://password@example.org:60000/?insecure=1&sni=iosapps.itunes.apple.com&mport=60000-65530#node-2"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	links, err := parseSubscriptionLinks(encoded)
	if err != nil {
		t.Fatalf("parseSubscriptionLinks() error = %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(links))
	}
	if !strings.HasPrefix(links[0], "vless://") || !strings.HasPrefix(links[1], "hysteria2://") {
		t.Fatalf("unexpected parsed links: %#v", links)
	}
}

func TestConvertVlessNode(t *testing.T) {
	link := "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=ws&security=tls&sni=www.example.com&fp=chrome&insecure=0&host=ws.example.com&path=%2Fws&encryption=none#vless-node"
	outbound, err := convertNodeLink(link, 1)
	if err != nil {
		t.Fatalf("convertNodeLink() error = %v", err)
	}

	if outbound["protocol"] != "vless" {
		t.Fatalf("protocol = %v, want vless", outbound["protocol"])
	}
	if outbound["tag"] != "vless-node" {
		t.Fatalf("tag = %v, want vless-node", outbound["tag"])
	}

	settings := outbound["settings"].(map[string]any)
	vnext := settings["vnext"].([]any)
	server := vnext[0].(map[string]any)
	users := server["users"].([]any)
	user := users[0].(map[string]any)
	if user["encryption"] != "none" {
		t.Fatalf("encryption = %v, want none", user["encryption"])
	}

	stream := outbound["streamSettings"].(map[string]any)
	if stream["network"] != "websocket" {
		t.Fatalf("network = %v, want websocket", stream["network"])
	}
	if stream["security"] != "tls" {
		t.Fatalf("security = %v, want tls", stream["security"])
	}
	ws := stream["wsSettings"].(map[string]any)
	if ws["host"] != "ws.example.com" || ws["path"] != "/ws" {
		t.Fatalf("unexpected ws settings: %#v", ws)
	}
	tlsSettings := stream["tlsSettings"].(map[string]any)
	if tlsSettings["serverName"] != "www.example.com" || tlsSettings["fingerprint"] != "chrome" {
		t.Fatalf("unexpected tls settings: %#v", tlsSettings)
	}
}

func TestConvertHysteria2Node(t *testing.T) {
	link := "hysteria2://password@example.org:60000/?insecure=1&sni=iosapps.itunes.apple.com&mport=60000-65530#hy2-node"
	outbound, err := convertNodeLink(link, 1)
	if err != nil {
		t.Fatalf("convertNodeLink() error = %v", err)
	}

	if outbound["protocol"] != "hysteria" {
		t.Fatalf("protocol = %v, want hysteria", outbound["protocol"])
	}
	if outbound["tag"] != "hy2-node" {
		t.Fatalf("tag = %v, want hy2-node", outbound["tag"])
	}

	settings := outbound["settings"].(map[string]any)
	if settings["version"] != 2 || settings["address"] != "example.org" || settings["port"] != 60000 {
		t.Fatalf("unexpected hysteria settings: %#v", settings)
	}

	stream := outbound["streamSettings"].(map[string]any)
	if stream["network"] != "hysteria" || stream["security"] != "tls" {
		t.Fatalf("unexpected stream basics: %#v", stream)
	}
	tlsSettings := stream["tlsSettings"].(map[string]any)
	if tlsSettings["serverName"] != "iosapps.itunes.apple.com" || tlsSettings["allowInsecure"] != true {
		t.Fatalf("unexpected tls settings: %#v", tlsSettings)
	}
	hySettings := stream["hysteriaSettings"].(map[string]any)
	if hySettings["version"] != 2 || hySettings["auth"] != "password" {
		t.Fatalf("unexpected hysteria transport settings: %#v", hySettings)
	}
	quicSettings := stream["quicSettings"].(map[string]any)
	extra := quicSettings["extra"].(map[string]any)
	udpHop := extra["udphop"].(map[string]any)
	if udpHop["ports"] != "60000-65530" {
		t.Fatalf("unexpected udphop ports: %#v", udpHop)
	}
}

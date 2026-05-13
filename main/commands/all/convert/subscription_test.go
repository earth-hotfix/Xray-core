package convert

import (
	"encoding/base64"
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
}

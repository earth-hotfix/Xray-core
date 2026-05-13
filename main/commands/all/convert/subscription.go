package convert

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdSubscription = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} convert subscription [-i input_file|-s subscription] [-o output_file|-]",
	Short:       "Convert subscription links into a usable Xray config",
	Long: `
Parse subscription content (base64 text or plain links) and generate a Xray JSON config.
Supported node schemes: vless://, hysteria2://

Arguments:

	-i file, -input file
		Read subscription content from file. Use '-' for stdin.

	-s text, -subscription text
		Directly provide subscription content text.

	-o file, -output file
		Write generated Xray config to file. Use '-' for stdout. Default: config.json

	-strict
		Stop when any node cannot be converted.

Examples:

	{{.Exec}} convert subscription -i sub.txt -o config.json
	{{.Exec}} convert subscription -s "<base64_subscription>" -o -
`,
	Run: executeConvertSubscription,
}

func executeConvertSubscription(cmd *base.Command, args []string) {
	var inputFile, inputText, outputFile string
	var strict bool

	cmd.Flag.StringVar(&inputFile, "i", "", "")
	cmd.Flag.StringVar(&inputFile, "input", "", "")
	cmd.Flag.StringVar(&inputText, "s", "", "")
	cmd.Flag.StringVar(&inputText, "subscription", "", "")
	cmd.Flag.StringVar(&outputFile, "o", "config.json", "")
	cmd.Flag.StringVar(&outputFile, "output", "config.json", "")
	cmd.Flag.BoolVar(&strict, "strict", false, "")
	cmd.Flag.Parse(args)

	content, err := loadSubscriptionContent(inputFile, inputText)
	if err != nil {
		base.Fatalf("failed to load subscription content: %v", err)
	}

	links, err := parseSubscriptionLinks(content)
	if err != nil {
		base.Fatalf("failed to parse subscription content: %v", err)
	}
	if len(links) == 0 {
		base.Fatalf("subscription contains no node links")
	}

	outbounds := make([]map[string]any, 0, len(links)+2)
	skipped := make([]string, 0)
	tagSeen := map[string]int{}
	for i, link := range links {
		outbound, err := convertNodeLink(link, i+1)
		if err != nil {
			if strict {
				base.Fatalf("failed to convert node %d: %v", i+1, err)
			}
			skipped = append(skipped, fmt.Sprintf("node %d: %v", i+1, err))
			continue
		}
		outbound["tag"] = dedupeTag(outbound["tag"].(string), tagSeen)
		outbounds = append(outbounds, outbound)
	}

	if len(outbounds) == 0 {
		base.Fatalf("no supported nodes were converted")
	}

	outbounds = append(outbounds,
		map[string]any{
			"tag":      "direct",
			"protocol": "freedom",
		},
		map[string]any{
			"tag":      "block",
			"protocol": "blackhole",
		},
	)

	config := buildConfig(outbounds)
	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		base.Fatalf("failed to marshal config: %v", err)
	}

	if outputFile == "-" {
		fmt.Println(string(output))
	} else {
		if err := os.WriteFile(outputFile, output, 0o644); err != nil {
			base.Fatalf("failed to write output file: %v", err)
		}
		fmt.Printf("Generated config with %d outbounds -> %s\n", len(outbounds), outputFile)
	}

	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "Skipped %d node(s):\n", len(skipped))
		for _, item := range skipped {
			fmt.Fprintf(os.Stderr, "  - %s\n", item)
		}
	}
}

func loadSubscriptionContent(inputFile, inputText string) (string, error) {
	if strings.TrimSpace(inputText) != "" {
		return inputText, nil
	}

	if inputFile == "" || inputFile == "-" {
		raw, err := io.ReadAll(os.Stdin)
		return string(raw), err
	}

	raw, err := os.ReadFile(inputFile)
	return string(raw), err
}

func parseSubscriptionLinks(content string) ([]string, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, fmt.Errorf("empty content")
	}

	if decoded, ok := decodeBase64Subscription(content); ok {
		content = decoded
	}

	lines := strings.FieldsFunc(content, func(r rune) bool {
		return r == '\r' || r == '\n'
	})

	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, line)
	}
	return result, nil
}

func decodeBase64Subscription(content string) (string, bool) {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, content)

	if compact == "" {
		return "", false
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	for _, enc := range encodings {
		decoded, err := enc.DecodeString(compact)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(decoded))
		if strings.Contains(text, "://") {
			return text, true
		}
	}
	return "", false
}

func convertNodeLink(link string, index int) (map[string]any, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return nil, fmt.Errorf("invalid node url: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "vless":
		return convertVlessNode(u, index)
	case "hysteria2", "hy2":
		return convertHysteria2Node(u, index)
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
}

func convertVlessNode(u *url.URL, index int) (map[string]any, error) {
	address := u.Hostname()
	if address == "" {
		return nil, fmt.Errorf("vless address is empty")
	}

	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}

	userID := u.User.Username()
	if userID == "" {
		return nil, fmt.Errorf("vless id is empty")
	}

	q := u.Query()
	network := normalizeNetwork(q.Get("type"))
	security := strings.ToLower(q.Get("security"))
	if security == "" {
		security = "none"
	}

	user := map[string]any{
		"id":         userID,
		"encryption": valueOrDefault(q.Get("encryption"), "none"),
	}
	if flow := q.Get("flow"); flow != "" {
		user["flow"] = flow
	}

	stream := map[string]any{
		"network": network,
	}
	if security != "none" {
		stream["security"] = security
	}

	switch security {
	case "none":
	case "tls":
		tlsSettings := map[string]any{}
		if serverName := q.Get("sni"); serverName != "" {
			tlsSettings["serverName"] = serverName
		}
		if fp := q.Get("fp"); fp != "" {
			tlsSettings["fingerprint"] = fp
		}
		if insecure := q.Get("insecure"); insecure != "" {
			tlsSettings["allowInsecure"] = parseBool(insecure)
		}
		if alpn := q.Get("alpn"); alpn != "" {
			tlsSettings["alpn"] = splitAndTrim(alpn, ",")
		}
		if len(tlsSettings) > 0 {
			stream["tlsSettings"] = tlsSettings
		}
	case "reality":
		realitySettings := map[string]any{
			"serverName":  q.Get("sni"),
			"fingerprint": valueOrDefault(q.Get("fp"), "chrome"),
			"publicKey":   q.Get("pbk"),
			"shortId":     q.Get("sid"),
			"spiderX":     valueOrDefault(q.Get("spx"), "/"),
		}
		if realitySettings["serverName"] == "" || realitySettings["publicKey"] == "" {
			return nil, fmt.Errorf("vless reality node missing required sni/pbk")
		}
		stream["realitySettings"] = realitySettings
	default:
		return nil, fmt.Errorf("unsupported vless security %q", security)
	}

	switch network {
	case "websocket":
		wsSettings := map[string]any{}
		if host := q.Get("host"); host != "" {
			wsSettings["host"] = host
		}
		if path := q.Get("path"); path != "" {
			wsSettings["path"] = path
		}
		if len(wsSettings) > 0 {
			stream["wsSettings"] = wsSettings
		}
	case "grpc":
		grpcSettings := map[string]any{}
		if serviceName := q.Get("serviceName"); serviceName != "" {
			grpcSettings["serviceName"] = serviceName
		}
		if authority := q.Get("authority"); authority != "" {
			grpcSettings["authority"] = authority
		}
		if len(grpcSettings) > 0 {
			stream["grpcSettings"] = grpcSettings
		}
	case "splithttp":
		splitHTTP := map[string]any{}
		if host := q.Get("host"); host != "" {
			splitHTTP["host"] = host
		}
		if path := q.Get("path"); path != "" {
			splitHTTP["path"] = path
		}
		if mode := q.Get("mode"); mode != "" {
			splitHTTP["mode"] = mode
		}
		if len(splitHTTP) > 0 {
			stream["splithttpSettings"] = splitHTTP
		}
	}

	return map[string]any{
		"tag":      decodeTag(u.Fragment, index),
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": address,
					"port":    port,
					"users":   []any{user},
				},
			},
		},
		"streamSettings": stream,
	}, nil
}

func convertHysteria2Node(u *url.URL, index int) (map[string]any, error) {
	address := u.Hostname()
	if address == "" {
		return nil, fmt.Errorf("hysteria2 address is empty")
	}

	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}

	auth := u.User.Username()
	if auth == "" {
		return nil, fmt.Errorf("hysteria2 auth is empty")
	}

	q := u.Query()
	hysteriaSettings := map[string]any{
		"version": 2,
		"auth":    auth,
	}
	if timeout := q.Get("udpIdleTimeout"); timeout != "" {
		if v, err := strconv.ParseInt(timeout, 10, 64); err == nil {
			hysteriaSettings["udpIdleTimeout"] = v
		}
	}

	stream := map[string]any{
		"network":  "hysteria",
		"security": "tls",
		"tlsSettings": map[string]any{
			"serverName":    valueOrDefault(q.Get("sni"), address),
			"allowInsecure": parseBool(q.Get("insecure")),
			"alpn":          []string{"h3"},
		},
		"hysteriaSettings": hysteriaSettings,
	}

	if hopPorts := q.Get("mport"); hopPorts != "" {
		stream["quicSettings"] = map[string]any{
			"extra": map[string]any{
				"udphop": map[string]any{
					"ports": hopPorts,
				},
			},
		}
	}

	return map[string]any{
		"tag":      decodeTag(u.Fragment, index),
		"protocol": "hysteria",
		"settings": map[string]any{
			"version": 2,
			"address": address,
			"port":    port,
		},
		"streamSettings": stream,
	}, nil
}

func buildConfig(outbounds []map[string]any) map[string]any {
	return map[string]any{
		"log": map[string]any{
			"loglevel": "warning",
		},
		"inbounds": []any{
			map[string]any{
				"tag":      "socks-in",
				"listen":   "127.0.0.1",
				"port":     10808,
				"protocol": "socks",
				"settings": map[string]any{"udp": true},
			},
			map[string]any{
				"tag":      "http-in",
				"listen":   "127.0.0.1",
				"port":     10809,
				"protocol": "http",
			},
		},
		"outbounds": outbounds,
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{
					"type":        "field",
					"network":     "tcp,udp",
					"outboundTag": outbounds[0]["tag"],
				},
			},
		},
	}
}

func parsePort(port string) (int, error) {
	if port == "" {
		return 0, fmt.Errorf("missing port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", port)
	}
	return p, nil
}

func decodeTag(fragment string, index int) string {
	if fragment == "" {
		return fmt.Sprintf("node-%03d", index)
	}
	tag, err := url.QueryUnescape(fragment)
	if err != nil {
		tag = fragment
	}
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return fmt.Sprintf("node-%03d", index)
	}
	return tag
}

func dedupeTag(tag string, seen map[string]int) string {
	if seen[tag] == 0 {
		seen[tag] = 1
		return tag
	}
	seen[tag]++
	return fmt.Sprintf("%s-%d", tag, seen[tag])
}

func normalizeNetwork(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "tcp", "raw":
		return "tcp"
	case "ws", "websocket":
		return "websocket"
	case "grpc":
		return "grpc"
	case "splithttp", "xhttp":
		return "splithttp"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func valueOrDefault(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}

func splitAndTrim(value, sep string) []string {
	parts := strings.Split(value, sep)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

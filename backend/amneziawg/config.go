// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config is a distinct AWG device configuration; peer credentials use the existing protobuf shape.
type Config struct {
	InterfaceName string                     `json:"interface_name"`
	PrivateKey    string                     `json:"private_key"`
	PreSharedKey  string                     `json:"pre_shared_key,omitempty"`
	ListenPort    int                        `json:"listen_port"`
	Address       []string                   `json:"address"`
	AWG           map[string]json.RawMessage `json:"awg"`
	deviceUAPI    string
	psk           string
	publicKey     string
	networks      []*net.IPNet
}

var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
var rangePattern = regexp.MustCompile(`^[0-9]+(-[0-9]+)?$`)

// The bounded Phase 1 mapping is the intersection of the pinned Go UAPI and tools parser.
var rangeFields = map[string]uint64{
	"h1": 4294967295, "h2": 4294967295, "h3": 4294967295, "h4": 4294967295,
	"content_padding_addition": 65535, "rekey_after_time": 65535, "rekey_timeout": 65535,
	"reject_after_time": 65535, "keepalive_timeout": 65535, "max_handshake_attempts": 65535,
}
var integerFields = map[string]bool{"jc": true, "jmin": true, "jmax": true, "s1": true, "s2": true, "s3": true, "s4": true}

func parseRange(s string, max uint64) (uint64, uint64, error) {
	if !rangePattern.MatchString(s) {
		return 0, 0, errors.New("expected decimal value or ascending range")
	}
	parts := strings.Split(s, "-")
	lo, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || lo > max {
		return 0, 0, errors.New("range exceeds supported width")
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil || hi > max || hi < lo {
			return 0, 0, errors.New("invalid range bound")
		}
	}
	return lo, hi, nil
}

func keyHex(s string) (string, error) {
	key, err := wgtypes.ParseKey(s)
	if err != nil || key == (wgtypes.Key{}) {
		return "", errors.New("expected a nonzero base64 32-byte key")
	}
	return hex.EncodeToString(key[:]), nil
}

func privateKeyHex(s string) (string, error) {
	key, err := wgtypes.ParseKey(s)
	if err != nil || key == (wgtypes.Key{}) {
		return "", errors.New("expected a nonzero base64 32-byte key")
	}
	// The pinned official Device clamps NoisePrivateKey in FromMaybeZeroHex
	// before storing and returning it through UAPI. Send and verify that exact
	// effective scalar so existing panel-generated raw keys survive read-back.
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	return hex.EncodeToString(key[:]), nil
}

func NewConfig(raw string) (*Config, error) {
	if len(raw) > 64<<10 {
		return nil, errors.New("AWG configuration exceeds 64 KiB")
	}
	c := new(Config)
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(c); err != nil {
		return nil, errors.New("invalid AWG configuration JSON or unknown field")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("unexpected trailing configuration")
	}
	if !interfacePattern.MatchString(c.InterfaceName) {
		return nil, errors.New("AWG requires an explicit safe interface_name")
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return nil, errors.New("listen_port outside 0..65535")
	}
	if len(c.Address) == 0 || len(c.Address) > 8 {
		return nil, errors.New("AWG requires address prefixes")
	}
	for _, s := range c.Address {
		_, n, e := net.ParseCIDR(s)
		if e != nil {
			return nil, errors.New("invalid interface address")
		}
		c.networks = append(c.networks, n)
	}
	private, err := privateKeyHex(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private_key: %w", err)
	}
	serverPrivate, _ := wgtypes.ParseKey(c.PrivateKey)
	serverPublic := serverPrivate.PublicKey()
	c.publicKey = hex.EncodeToString(serverPublic[:])
	if c.PreSharedKey != "" {
		c.psk, err = keyHex(c.PreSharedKey)
		if err != nil {
			return nil, fmt.Errorf("pre_shared_key: %w", err)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\n", private, c.ListenPort)
	keys := make([]string, 0, len(c.AWG))
	for key := range c.AWG {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := map[string]string{}
	for _, key := range keys {
		raw := c.AWG[key]
		var value string
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, fmt.Errorf("AWG %s cannot be null", key)
		}
		switch {
		case integerFields[key]:
			var n uint16
			if json.Unmarshal(raw, &n) != nil {
				return nil, fmt.Errorf("AWG %s requires an unsigned 16-bit integer", key)
			}
			value = strconv.FormatUint(uint64(n), 10)
		case rangeFields[key] > 0:
			if json.Unmarshal(raw, &value) != nil {
				return nil, fmt.Errorf("AWG %s requires a range string", key)
			}
			if _, _, err := parseRange(value, rangeFields[key]); err != nil {
				return nil, fmt.Errorf("AWG %s: %w", key, err)
			}
		case key == "header_protection_key":
			var encoded string
			if json.Unmarshal(raw, &encoded) != nil {
				return nil, errors.New("invalid header_protection_key type")
			}
			value, err = keyHex(encoded)
			if err != nil {
				return nil, fmt.Errorf("header_protection_key: %w", err)
			}
		case key == "random_trailers" || key == "disable_cookies":
			var v bool
			if json.Unmarshal(raw, &v) != nil {
				return nil, fmt.Errorf("AWG %s requires boolean", key)
			}
			if key == "disable_cookies" && v {
				return nil, errors.New("disabling cookie protection is prohibited")
			}
			value = strconv.FormatBool(v)
		default:
			return nil, fmt.Errorf("unsupported AWG field %q", key)
		}
		values[key] = value
		fmt.Fprintf(&b, "%s=%s\n", key, value)
	}
	if values["header_protection_key"] != "" {
		for _, key := range []string{"s1", "s2", "s3", "s4"} {
			n, _ := strconv.Atoi(values[key])
			if n < 12 {
				return nil, errors.New("header protection requires S1-S4 >= 12")
			}
		}
	}
	min, _ := strconv.Atoi(values["jmin"])
	max, _ := strconv.Atoi(values["jmax"])
	if min > max {
		return nil, errors.New("jmin must not exceed jmax")
	}
	headerNames := []string{"h1", "h2", "h3", "h4"}
	bounds := make([][2]uint64, 4)
	for i, k := range headerNames {
		s := values[k]
		if s == "" {
			s = strconv.Itoa(i + 1)
		}
		lo, hi, _ := parseRange(s, 4294967295)
		bounds[i] = [2]uint64{lo, hi}
	}
	for i := range bounds {
		for j := 0; j < i; j++ {
			if bounds[i][0] <= bounds[j][1] && bounds[j][0] <= bounds[i][1] {
				return nil, errors.New("AWG header ranges must not overlap")
			}
		}
	}
	if _, ok := values["disable_cookies"]; !ok {
		b.WriteString("disable_cookies=false\n")
	}
	c.deviceUAPI = b.String()
	return c, nil
}

package api

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Multi-hop routing, reverse-engineered from the Android SDK
// (QyMultiLinkHop / QyUnifiedProcessStrategy):
//
//  1. GET  /api/accelerate_bff/v1/multi_hop_all_node   -> encrypted list of hop entry candidates
//  2. the client measures its own delay to each candidate
//  3. POST /api/accelerate_bff/v2/multi_hop_shortest_path with the encrypted delays
//     -> encrypted ranked paths (area_nodes) plus an independent second set
//     (replicas_area_nodes) used for a parallel link
//  4. the best paths become top-level "multiLink" entries in the QyProxy start config.
//
// Payloads use the SDK's shared key (QyAccConfig.commonAesDesKey): AES-128-ECB,
// key = first 16 hex chars of md5(sdkKey), zero padding, hex encoding.
const sdkCommonKey = "43571366E30F489F"

func sdkAESKey() []byte {
	sum := md5.Sum([]byte(sdkCommonKey))
	return []byte(hex.EncodeToString(sum[:])[:16])
}

// EncryptSDK encrypts plaintext the way the SDK does for crypto_delay_info.
func EncryptSDK(plain []byte) string {
	block, _ := aes.NewCipher(sdkAESKey())
	buf := append([]byte(nil), plain...)
	if r := len(buf) % aes.BlockSize; r != 0 {
		buf = append(buf, make([]byte, aes.BlockSize-r)...)
	}
	out := make([]byte, len(buf))
	for i := 0; i < len(buf); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], buf[i:i+aes.BlockSize])
	}
	return strings.ToUpper(hex.EncodeToString(out))
}

// DecryptSDK reverses EncryptSDK, stripping zero/PKCS padding.
func DecryptSDK(hexStr string) ([]byte, error) {
	ct, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil {
		return nil, fmt.Errorf("invalid hex payload: %w", err)
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("payload length %d is not a multiple of %d", len(ct), aes.BlockSize)
	}
	block, _ := aes.NewCipher(sdkAESKey())
	pt := make([]byte, len(ct))
	for i := 0; i < len(ct); i += aes.BlockSize {
		block.Decrypt(pt[i:i+aes.BlockSize], ct[i:i+aes.BlockSize])
	}
	// The SDK strips non-printable bytes after decrypting; padding bytes are
	// either NUL (zero padding) or 0x01-0x10 (PKCS#5), all non-printable.
	pt = bytes.TrimRightFunc(pt, func(r rune) bool { return r < 0x20 })
	return pt, nil
}

// HopCandidate is a possible first hop returned by multi_hop_all_node.
type HopCandidate struct {
	Type       int    `json:"type"`
	IP         string `json:"ip"`
	UdpingPort []int  `json:"udping_port"`
}

// HopDelay is one measured delay sent back to the server.
type HopDelay struct {
	IP    string  `json:"ip"`
	Delay float64 `json:"delay"`
}

// HopPathEntry is one hop of a multi-hop path.
type HopPathEntry struct {
	IP            string `json:"ip"`
	TCPPort       []int  `json:"tcp_port"`
	UDPPort       []int  `json:"udp_port"`
	ForceProtocol string `json:"force_protocol"`
}

// MultiHopNode is one ranked path from multi_hop_shortest_path.
type MultiHopNode struct {
	ID          int            `json:"id"`
	PublicIP    string         `json:"publicip"`
	Delay       float64        `json:"delay"`
	Des         []float64      `json:"des"`
	Path        []HopPathEntry `json:"path"`
	IsMultilink bool           `json:"is_multilink_node"`
	LinkStart   string         `json:"link_start_name"`
	LinkEnd     string         `json:"link_end_name"`
}

type multiHopArea struct {
	Area  string         `json:"area"`
	Nodes []MultiHopNode `json:"nodes"`
}

// GetMultiHopCandidates fetches and decrypts the hop entry candidates for a game zone.
func (c *Client) GetMultiHopCandidates(gameID, zoneID int) ([]HopCandidate, error) {
	q := url.Values{}
	q.Set("version", "2.2.0.0")
	q.Set("client_type", "20")
	q.Set("crypto_method", "AES-ECB")
	q.Set("game_id", fmt.Sprintf("%d", gameID))
	q.Set("zone_id", fmt.Sprintf("%d", zoneID))

	respBytes, err := c.doRequest(http.MethodGet, "/api/accelerate_bff/v1/multi_hop_all_node", q, nil)
	if err != nil {
		return nil, fmt.Errorf("multi_hop_all_node: %w", err)
	}
	var resp struct {
		NodeList string `json:"node_list"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("parse multi_hop_all_node: %w", err)
	}
	if resp.NodeList == "" {
		return nil, errors.New("multi_hop_all_node returned no node_list")
	}
	plain, err := DecryptSDK(resp.NodeList)
	if err != nil {
		return nil, err
	}
	var cands []HopCandidate
	if err := json.Unmarshal(plain, &cands); err != nil {
		return nil, fmt.Errorf("parse decrypted hop candidates: %w", err)
	}
	return cands, nil
}

// GetShortestPaths submits measured delays and returns the ranked main paths
// and the independent replica paths (for a parallel second link), each sorted
// by server-estimated delay to the game server.
func (c *Client) GetShortestPaths(gameID, zoneID int, delays []HopDelay) (main, replicas []MultiHopNode, err error) {
	if len(delays) == 0 {
		return nil, nil, errors.New("no hop delays to submit")
	}
	plain, err := json.Marshal(delays)
	if err != nil {
		return nil, nil, err
	}
	// Large: must go in a POST body (a GET query hits nginx 414).
	body := map[string]string{
		"game_id":           fmt.Sprintf("%d", gameID),
		"zone_id":           fmt.Sprintf("%d", zoneID),
		"crypto_method":     "AES-ECB",
		"crypto_delay_info": EncryptSDK(plain),
	}
	respBytes, err := c.doRequest(http.MethodPost, "/api/accelerate_bff/v2/multi_hop_shortest_path", nil, body)
	if err != nil {
		return nil, nil, fmt.Errorf("multi_hop_shortest_path: %w", err)
	}
	var resp struct {
		AreaNodes         string `json:"area_nodes"`
		ReplicasAreaNodes string `json:"replicas_area_nodes"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, nil, fmt.Errorf("parse multi_hop_shortest_path: %w", err)
	}
	if main, err = decodeAreaNodes(resp.AreaNodes); err != nil {
		return nil, nil, fmt.Errorf("area_nodes: %w", err)
	}
	replicas, _ = decodeAreaNodes(resp.ReplicasAreaNodes) // optional
	return main, replicas, nil
}

func decodeAreaNodes(enc string) ([]MultiHopNode, error) {
	if enc == "" {
		return nil, errors.New("empty")
	}
	plain, err := DecryptSDK(enc)
	if err != nil {
		return nil, err
	}
	var areas []multiHopArea
	if err := json.Unmarshal(plain, &areas); err != nil {
		return nil, err
	}
	var nodes []MultiHopNode
	for _, a := range areas {
		nodes = append(nodes, a.Nodes...)
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].Delay < nodes[j].Delay })
	return nodes, nil
}

// Entry hop transports for BuildMultiLink.
const (
	EntryTCP = "tcp" // SDK default
	EntryUDP = "udp" // opt-in: avoids TCP head-of-line stalls on the first hop
)

// ParseEntryProto validates a multihop_entry setting; empty means EntryTCP.
func ParseEntryProto(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", EntryTCP:
		return EntryTCP, nil
	case EntryUDP:
		return EntryUDP, nil
	}
	return EntryTCP, fmt.Errorf("unknown multi-hop entry protocol %q (want tcp or udp)", v)
}

// BuildMultiLink converts a ranked path into a QyProxy "multiLink" entry,
// mirroring QyUnifiedProcessStrategy.multiLinkHopZoneNodesAssembleLogic:
// server = entry IP, port = entry's first TCP port, and path = the entry hop
// (proc "tcp") followed by the remaining hops in order.
//
// The SDK always uses TCP for the entry hop, so game UDP rides inside TCP on
// the client's own link and every lost segment stalls it. With entryProto
// EntryUDP the entry hop uses proc "udp" and its first UDP port instead; a
// path whose entry has no UDP port falls back to TCP. The returned string is
// the protocol actually used.
func BuildMultiLink(n MultiHopNode, entryProto string) (map[string]interface{}, string, error) {
	var entry *HopPathEntry
	for i := range n.Path {
		if n.Path[i].IP == n.PublicIP {
			entry = &n.Path[i]
			break
		}
	}
	if entry == nil || entry.IP == "" {
		return nil, "", fmt.Errorf("path %d has no hop matching entry %s", n.ID, n.PublicIP)
	}
	proto, port := EntryTCP, 0
	if entryProto == EntryUDP && len(entry.UDPPort) > 0 {
		proto, port = EntryUDP, entry.UDPPort[0]
	} else if len(entry.TCPPort) > 0 {
		port = entry.TCPPort[0]
	} else {
		return nil, "", fmt.Errorf("path %d entry %s has no tcp_port", n.ID, n.PublicIP)
	}

	hop := func(p HopPathEntry, proc string) map[string]interface{} {
		m := map[string]interface{}{
			"ip":       p.IP,
			"tcp_port": nonNilInts(p.TCPPort),
			"udp_port": nonNilInts(p.UDPPort),
		}
		if proc != "" {
			m["proc"] = proc
		}
		return m
	}
	path := []interface{}{hop(*entry, proto)}
	for _, p := range n.Path {
		if p.IP != n.PublicIP {
			path = append(path, hop(p, p.ForceProtocol))
		}
	}
	return map[string]interface{}{
		"server": n.PublicIP,
		"port":   port,
		"delay":  int(n.Delay),
		"path":   path,
	}, proto, nil
}

func nonNilInts(v []int) []int {
	if v == nil {
		return []int{}
	}
	return v
}

// PublicHopIPs returns the distinct public (routable) hop addresses of the
// given paths. Private addresses are inside the provider's backbone and are
// never reached directly by this host.
func PublicHopIPs(nodes ...MultiHopNode) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range nodes {
		for _, p := range n.Path {
			ip := net.ParseIP(p.IP)
			if ip == nil || ip.To4() == nil || ip.IsPrivate() || ip.IsLoopback() || seen[p.IP] {
				continue
			}
			seen[p.IP] = true
			out = append(out, p.IP)
		}
	}
	return out
}

// PickLinks chooses the main path and, when available, a parallel link with a
// different entry hop from the replica set, so the two links do not share a
// first hop (and its local congestion).
func PickLinks(main, replicas []MultiHopNode) []MultiHopNode {
	if len(main) == 0 {
		return nil
	}
	picked := []MultiHopNode{main[0]}
	for _, r := range append(append([]MultiHopNode(nil), replicas...), main[1:]...) {
		if r.PublicIP != "" && r.PublicIP != main[0].PublicIP {
			picked = append(picked, r)
			break
		}
	}
	return picked
}

// MultiHopPlan is the result of the full multi-hop selection for one connect.
type MultiHopPlan struct {
	Links       []map[string]interface{} // top-level "multiLink" entries
	Chosen      []MultiHopNode           // the paths behind Links, best first
	EntryProtos []string                 // entry hop protocol used per link
	BypassIPs   []string                 // public hop IPs that must bypass the tunnel
	Measured    int                      // candidates that answered ICMP
}

// PlanMultiHop runs candidates -> ICMP delays -> shortest paths -> links.
// It needs no tunnel and is safe to run while other connect work proceeds.
func (c *Client) PlanMultiHop(gameID, zoneID int, entryProto string) (*MultiHopPlan, error) {
	cands, err := c.GetMultiHopCandidates(gameID, zoneID)
	if err != nil {
		return nil, err
	}
	delays := MeasureHopDelays(cands, 3, time.Second, 40)
	if len(delays) == 0 {
		return nil, fmt.Errorf("none of %d hop candidates answered ICMP", len(cands))
	}
	main, replicas, err := c.GetShortestPaths(gameID, zoneID, delays)
	if err != nil {
		return nil, err
	}
	plan := &MultiHopPlan{Measured: len(delays)}
	for _, n := range PickLinks(main, replicas) {
		link, proto, err := BuildMultiLink(n, entryProto)
		if err != nil {
			continue
		}
		plan.Links = append(plan.Links, link)
		plan.Chosen = append(plan.Chosen, n)
		plan.EntryProtos = append(plan.EntryProtos, proto)
	}
	if len(plan.Links) == 0 {
		return nil, fmt.Errorf("server returned %d paths but none were usable", len(main))
	}
	plan.BypassIPs = PublicHopIPs(plan.Chosen...)
	return plan, nil
}

package nm

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/lagofast/lagofast-vpn/pkg/api"
	"github.com/lagofast/lagofast-vpn/pkg/model"
	"github.com/lagofast/lagofast-vpn/pkg/tunnel"
)

const (
	DBusInterface = "org.freedesktop.NetworkManager.VPN.Plugin"
	DBusObjectPath = "/org/freedesktop/NetworkManager/VPN/Plugin"
	DBusService   = "org.freedesktop.NetworkManager.lagofast"

	// NetworkManager VPN Service States
	StateUnknown     uint32 = 0
	StateInit        uint32 = 1
	StateStarting    uint32 = 2
	StateConfiguring uint32 = 3
	StateStarted     uint32 = 4
	StateStopping    uint32 = 5
	StateStopped     uint32 = 6

	// NetworkManager VPN Errors
	ErrorNone                   uint32 = 0
	ErrorUserCanceled           uint32 = 1
	ErrorDeviceFailed           uint32 = 2
	ErrorDeviceRemoved          uint32 = 3
	ErrorConfigFailed           uint32 = 4
	ErrorConfigUnavailable      uint32 = 5
	ErrorConnectionInvalid      uint32 = 6
	ErrorConnectionRemoved      uint32 = 7
	ErrorServiceStartFailed     uint32 = 8
	ErrorServiceStartTimeout    uint32 = 9
	ErrorServiceStopped         uint32 = 10
	ErrorServiceExecutionFailed uint32 = 11
)

type PluginService struct {
	conn         *dbus.Conn
	state        uint32
	tunDev       *tunnel.Device
	apiClient    *api.Client
	session      *model.UserSession
	activeGame   *model.GameItem
	activeNode   *model.NodeItem
	routeCleanup func()
}

func NewPluginService() (*PluginService, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to system bus: %w", err)
	}

	reply, err := conn.RequestName(DBusService, dbus.NameFlagDoNotQueue)
	if err != nil {
		return nil, fmt.Errorf("failed to request D-Bus name: %w", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return nil, fmt.Errorf("name %s already taken", DBusService)
	}

	s := &PluginService{
		conn:      conn,
		state:     StateInit,
		apiClient: api.NewClient(""),
	}

	err = conn.Export(s, DBusObjectPath, DBusInterface)
	if err != nil {
		return nil, fmt.Errorf("failed to export D-Bus interface: %w", err)
	}

	return s, nil
}

func (s *PluginService) setState(state uint32) {
	s.state = state
	err := s.conn.Emit(DBusObjectPath, DBusInterface+".StateChanged", state)
	if err != nil {
		log.Printf("[D-Bus] Error emitting StateChanged(%d): %v", state, err)
	}
}

func (s *PluginService) emitFailure(reason uint32) {
	s.setState(StateStopped)
	s.conn.Emit(DBusObjectPath, DBusInterface+".Failure", reason)
}

// NeedSecrets is invoked by NetworkManager to determine if credentials are required
func (s *PluginService) NeedSecrets(connection map[string]map[string]dbus.Variant) (string, *dbus.Error) {
	log.Printf("[NM-LagoFast] Received NeedSecrets check from NetworkManager")
	session, err := model.LoadSession()
	if err != nil {
		vpnData, ok := connection["vpn"]
		if !ok {
			return "vpn", nil
		}
		token, _ := vpnData["token"].Value().(string)
		pwd, _ := vpnData["password"].Value().(string)
		if token == "" && pwd == "" {
			return "vpn", nil
		}
		return "", nil
	}

	if session == nil || session.Token == "" {
		return "vpn", nil
	}

	log.Printf("[NM-LagoFast] Valid local session found (UID: %s). No secrets needed.", session.UID)
	return "", nil
}

// ConnectInteractive is invoked when interactive secrets are provided
func (s *PluginService) ConnectInteractive(connection map[string]map[string]dbus.Variant, details map[string]dbus.Variant) *dbus.Error {
	return s.Connect(connection)
}

func setupBypassRoutes(nodeIP string, bypassCIDRs []string) (func(), error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return func() {}, err
	}
	fields := strings.Fields(string(out))
	var gw, dev string
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "via" && gw == "" {
			gw = fields[i+1]
		}
		if fields[i] == "dev" && dev == "" {
			dev = fields[i+1]
		}
	}
	if gw == "" || dev == "" {
		return func() {}, fmt.Errorf("unable to determine default gateway")
	}

	tunnel.DefaultEngine.SetBindInterface(dev)
	exec.Command("ip", "route", "replace", nodeIP+"/32", "via", gw, "dev", dev).Run()
	for _, cidr := range bypassCIDRs {
		exec.Command("ip", "route", "replace", cidr, "via", gw, "dev", dev).Run()
	}

	cleanup := func() {
		exec.Command("ip", "route", "del", nodeIP+"/32", "via", gw, "dev", dev).Run()
		for _, cidr := range bypassCIDRs {
			exec.Command("ip", "route", "del", cidr, "via", gw, "dev", dev).Run()
		}
	}
	return cleanup, nil
}

// Connect is invoked by NetworkManager when initiating a VPN connection
func (s *PluginService) Connect(connection map[string]map[string]dbus.Variant) *dbus.Error {
	log.Printf("[NM-LagoFast] Received Connect request from NetworkManager")
	s.setState(StateStarting)

	vpnData, ok := connection["vpn"]
	if !ok {
		s.emitFailure(ErrorConnectionInvalid)
		return dbus.NewError("org.freedesktop.NetworkManager.VPN.Error.ConnectionInvalid", []interface{}{"missing vpn section"})
	}

	username, _ := vpnData["username"].Value().(string)
	password, _ := vpnData["password"].Value().(string)
	token, _ := vpnData["token"].Value().(string)
	gameIDStr, _ := vpnData["game_id"].Value().(string)

	log.Printf("[NM-LagoFast] Authenticating user %s...", username)
	if token != "" {
		s.apiClient.SetToken(token, "")
	} else if username != "" && password != "" {
		session, err := s.apiClient.Login(username, password)
		if err != nil {
			log.Printf("[NM-LagoFast] Login failed: %v", err)
			s.emitFailure(ErrorConfigFailed)
			return dbus.NewError("org.freedesktop.NetworkManager.VPN.Error.ConfigFailed", []interface{}{err.Error()})
		}
		s.session = session
		log.Printf("[NM-LagoFast] Authenticated successfully, UID: %s", session.UID)
	} else {
		// Attempt to load existing saved session (e.g. from Google OAuth)
		session, err := model.LoadSession()
		if err != nil || session == nil || session.Token == "" {
			log.Printf("[NM-LagoFast] No credentials provided and no active saved session found: %v", err)
			s.emitFailure(ErrorConfigUnavailable)
			return dbus.NewError("org.freedesktop.NetworkManager.VPN.Error.ConfigUnavailable", []interface{}{"No credentials provided and no saved session found. Please run 'lagofast login --google' first."})
		}
		s.session = session
		s.apiClient.SetToken(session.Token, session.UID)
		log.Printf("[NM-LagoFast] Loaded active saved session for account %s (UID: %s)", session.Account, session.UID)
	}

	s.setState(StateConfiguring)

	gameID := 54758
	if gameIDStr != "" {
		parsedID, parseErr := strconv.Atoi(gameIDStr)
		if parseErr != nil {
			log.Printf("[NM-LagoFast] Invalid game_id %q, defaulting to %d", gameIDStr, gameID)
		} else {
			gameID = parsedID
		}
	}

	zoneID := 0
	if gameID == 54758 {
		zoneID = 45983
	}
	if zoneIDStr, ok := vpnData["zone_id"].Value().(string); ok && zoneIDStr != "" {
		if zid, err := strconv.Atoi(zoneIDStr); err == nil {
			zoneID = zid
		}
	}

	explicitNodeIP, _ := vpnData["node_ip"].Value().(string)
	if explicitNodeIP != "" && explicitNodeIP != "auto" {
		log.Printf("[NM-LagoFast] Using explicit node IP from settings: %s", explicitNodeIP)
		s.activeNode = &model.NodeItem{
			NodeIP:   explicitNodeIP,
			Port:     9993,
			NodeName: "Configured-Node",
		}
	} else if zoneID > 0 {
		log.Printf("[NM-LagoFast] Running smart multi-probe stability benchmark (Game ID %d, Zone ID %d)...", gameID, zoneID)
		bestNode, rtt, nodeErr := s.apiClient.SelectOptimalNodeForZone(gameID, zoneID)
		if nodeErr != nil {
			log.Printf("[NM-LagoFast] Zone node benchmark warning: %v, falling back to global", nodeErr)
			bestNode, rtt, nodeErr = s.apiClient.SelectOptimalNode(gameID)
		}
		if nodeErr != nil {
			log.Printf("[NM-LagoFast] Node benchmark warning: %v", nodeErr)
		} else {
			s.activeNode = bestNode
			log.Printf("[NM-LagoFast] Selected optimal node: %s (%s:%d) [RTT: %v]", bestNode.NodeName, bestNode.NodeIP, bestNode.Port, rtt)
		}
	} else {
		log.Printf("[NM-LagoFast] Benchmarking lowest latency relay node for Game ID %d...", gameID)
		bestNode, rtt, nodeErr := s.apiClient.SelectOptimalNode(gameID)
		if nodeErr != nil {
			log.Printf("[NM-LagoFast] Node benchmark warning: %v", nodeErr)
		} else {
			s.activeNode = bestNode
			log.Printf("[NM-LagoFast] Selected optimal node: %s (%s:%d) [RTT: %v]", bestNode.NodeName, bestNode.NodeIP, bestNode.Port, rtt)
		}
	}

	nodeIP := "43.153.212.197"
	nodePort := 9993
	if s.activeNode != nil {
		nodeIP = s.activeNode.NodeIP
		nodePort = s.activeNode.Port
	}

	var bypassCIDRs []string
	candidateNodes, candidateErr := s.apiClient.GetGameNodesForZone(gameID, zoneID)
	if candidateErr == nil {
		for _, cn := range candidateNodes {
			if cn.NodeIP != "" && cn.NodeIP != nodeIP {
				bypassCIDRs = append(bypassCIDRs, cn.NodeIP+"/32")
			}
		}
	}
	cleanupRoute, routeErr := setupBypassRoutes(nodeIP, bypassCIDRs)
	if routeErr != nil {
		log.Printf("[NM-LagoFast] Warning setting host route: %v", routeErr)
	} else {
		s.routeCleanup = cleanupRoute
	}

	log.Printf("[NM-LagoFast] Fetching acceleration credentials for Game ID %d, Zone ID %d...", gameID, zoneID)
	accountName := s.session.Account
	plainPwd := "tposwy"
	zoneFlag := "sg"

	acctDetail, detailErr := s.apiClient.GetAcctDetailAll(gameID, zoneID)
	if detailErr != nil {
		log.Printf("[NM-LagoFast] Warning: GetAcctDetailAll failed (%v), using default credentials", detailErr)
	} else {
		if acctDetail.Auth.AccountName != "" {
			accountName = acctDetail.Auth.AccountName
		}
		if acctDetail.SelectAcctFlag != "" {
			zoneFlag = acctDetail.SelectAcctFlag
		}
		decrypted, decErr := api.DecryptAcctPassword(s.session.UID, acctDetail.Auth.AccountPwd)
		if decErr != nil {
			log.Printf("[NM-LagoFast] Warning: DecryptAcctPassword failed (%v), fallback to default", decErr)
		} else if decrypted != "" {
			plainPwd = decrypted
		}
	}

	// Create TUN interface
	tunDev, err := tunnel.OpenTun("lagofast0", 1400)
	if err != nil {
		log.Printf("[NM-LagoFast] Failed to create TUN: %v", err)
		s.emitFailure(ErrorDeviceFailed)
		return dbus.NewError("org.freedesktop.NetworkManager.VPN.Error.DeviceFailed", []interface{}{err.Error()})
	}
	s.tunDev = tunDev

	groupIDStr := "320"
	if s.activeNode != nil && s.activeNode.GroupID > 0 {
		groupIDStr = fmt.Sprintf("%d", s.activeNode.GroupID)
	}

	gameConfig := map[string]interface{}{
		"confuse":            7,
		"enableProxyModeDNS": false,
		"enableUdpTunnel":    true,
		"log_level":          "DEBUG",
		"nat_open":           false,
	}
	if acctDetail != nil && acctDetail.CustomConfig != nil {
		if gc, ok := acctDetail.CustomConfig["qyproxy_game_config"].(map[string]interface{}); ok {
			for k, v := range gc {
				gameConfig[k] = v
			}
			// For PC games connecting directly by IP rather than DNS fake-IP,
			// enableProxyModeDNS MUST be false so lwIP does not drop direct IP sessions.
			gameConfig["enableProxyModeDNS"] = false
		}
	}

	// Construct QyProxy tunnel configuration
	tunnelConfig := map[string]interface{}{
		"server": map[string]interface{}{
			"address": nodeIP,
			"port":    nodePort,
		},
		"client": map[string]interface{}{
			"protocol":           "UDP",
			"group_id":           groupIDStr,
			"login_token":        s.session.Token,
			"username":           accountName,
			"password":           plainPwd,
			"client_type":        20,
			"eventId":            12345678,
			"sn":                 "c7a544b6-7917-488b-b892-06b297b1028b",
			"mode":               1,
			"serverid":           zoneID,
			"product_line": map[string]interface{}{
				"type":    "lagofast-android",
				"version": "2.2.0.0",
			},
			"select_zone_flag":   zoneFlag,
			"sessionSize":        0,
			"enableSpeedCounter": false,
			"ping_full_link":     false,
			"enableLwip":         true,
			"network_way":        "WIFI",
			"enableFineDivert":   false,
			"tunId":              "lagofast0",
		},
		"gameinfo": map[string]interface{}{
			"game_id": gameID,
		},
		"divert": map[string]interface{}{
			"confVersion": "1.0",
			"apiVersion":  "1.0",
			"dns": map[string]interface{}{
				"defaultOutTag": "direct",
				"servers": []map[string]interface{}{
					{"outTag": "direct", "domains": []string{"*"}},
				},
			},
			"routing": map[string]interface{}{
				"defaultOutTag": zoneFlag,
				"rules":         []interface{}{},
			},
		},
		"customProfile": map[string]interface{}{
			"qyproxy_config": map[string]interface{}{
				"game_area": zoneFlag,
			},
			"qyproxy_game_config": gameConfig,
		},
	}

	cfgBytes, _ := json.Marshal(tunnelConfig)
	if err := tunnel.DefaultEngine.Init(""); err != nil {
		log.Printf("[NM-LagoFast] Failed to initialize QyProxy engine: %v", err)
		s.tunDev.Close()
		s.tunDev = nil
		s.emitFailure(ErrorServiceStartFailed)
		return dbus.NewError("org.freedesktop.NetworkManager.VPN.Error.ServiceStartFailed", []interface{}{err.Error()})
	}
	log.Printf("[NM-LagoFast] Starting QyProxy tunnel engine on TUN fd %d...", int(tunDev.File.Fd()))
	if err := tunnel.DefaultEngine.Start(string(cfgBytes), int(tunDev.File.Fd())); err != nil {
		log.Printf("[NM-LagoFast] Failed to start QyProxy engine: %v", err)
		s.tunDev.Close()
		s.tunDev = nil
		s.emitFailure(ErrorServiceStartFailed)
		return dbus.NewError("org.freedesktop.NetworkManager.VPN.Error.ServiceStartFailed", []interface{}{err.Error()})
	}

	// Assign local IP (negotiated with QyProxy gateway)
	localIP := net.ParseIP("10.10.10.2")
	gatewayIP := net.ParseIP("10.10.10.1")
	dnsIP := net.ParseIP("8.8.8.8")

	// Assemble Subnet / CIDR routes dynamically from LagoFast REST API
	var routesList [][]uint32
	cidrs, err := s.apiClient.GetGameRoutingSubnets(gameID, zoneID)
	if err != nil {
		log.Printf("[NM-LagoFast] Dynamic routing subnets lookup failed: %v", err)
		cidrs = nil
	}
	seenCIDRs := make(map[string]bool)
	var combinedCIDRs []string
	for _, c := range cidrs {
		if !seenCIDRs[c] {
			seenCIDRs[c] = true
			combinedCIDRs = append(combinedCIDRs, c)
		}
	}
	log.Printf("[NM-LagoFast] Dynamically resolved %d routing subnets from LagoFast REST API for Game ID %d, Zone ID %d", len(combinedCIDRs), gameID, zoneID)
	nodeIPParsed := net.ParseIP(nodeIP)
	for _, cidr := range combinedCIDRs {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if nodeIPParsed != nil && ipnet.Contains(nodeIPParsed) {
			log.Printf("[NM-LagoFast] Excluding subnet %s containing relay node %s to avoid routing loop", cidr, nodeIP)
			continue
		}
		ones, _ := ipnet.Mask.Size()
		routesList = append(routesList, []uint32{
			ipToUint32(ip),
			uint32(ones),
			ipToUint32(gatewayIP),
			uint32(50),
		})
	}

	ip4Config := map[string]dbus.Variant{
		"tundev":        dbus.MakeVariant(tunDev.Name),
		"internal-ip4":  dbus.MakeVariant(ipToUint32(localIP)),
		"external-ip4":  dbus.MakeVariant(ipToUint32(net.ParseIP(nodeIP))),
		"address":       dbus.MakeVariant(ipToUint32(localIP)),
		"prefix":        dbus.MakeVariant(uint32(24)),
		"gateway":       dbus.MakeVariant(ipToUint32(gatewayIP)),
		"dns":           dbus.MakeVariant([]uint32{ipToUint32(dnsIP)}),
		"mtu":           dbus.MakeVariant(uint32(1400)),
		"never-default": dbus.MakeVariant(true),
		"routes":        dbus.MakeVariant(routesList),
	}

	log.Printf("[NM-LagoFast] Emitting Ip4Config on device %s", tunDev.Name)
	err = s.conn.Emit(DBusObjectPath, DBusInterface+".Ip4Config", ip4Config)
	if err != nil {
		log.Printf("[NM-LagoFast] Error emitting Ip4Config: %v", err)
	}

	s.setState(StateStarted)
	log.Printf("[NM-LagoFast] VPN connection established successfully (Game ID: %d)", gameID)
	return nil
}

// Disconnect is invoked by NetworkManager to terminate the connection
func (s *PluginService) Disconnect() *dbus.Error {
	log.Printf("[NM-LagoFast] Received Disconnect request")
	s.setState(StateStopping)

	tunnel.DefaultEngine.Stop()

	if s.tunDev != nil {
		s.tunDev.Close()
		s.tunDev = nil
	}

	if s.routeCleanup != nil {
		s.routeCleanup()
		s.routeCleanup = nil
	}

	s.setState(StateStopped)
	log.Printf("[NM-LagoFast] Disconnected cleanly")
	go func() {
		time.Sleep(200 * time.Millisecond)
		os.Exit(0)
	}()
	return nil
}

// SetConfig sets additional runtime plugin configurations
func (s *PluginService) SetConfig(config map[string]dbus.Variant) *dbus.Error {
	return nil
}

// SetIp4Config confirmation from NM
func (s *PluginService) SetIp4Config(config map[string]dbus.Variant) *dbus.Error {
	return nil
}

// SetIp6Config confirmation from NM
func (s *PluginService) SetIp6Config(config map[string]dbus.Variant) *dbus.Error {
	return nil
}

// SetFailure handles failure notifications
func (s *PluginService) SetFailure(reason string) *dbus.Error {
	s.emitFailure(ErrorConfigFailed)
	return nil
}

func (s *PluginService) Run() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("[NM-LagoFast] Service running on D-Bus (%s)", DBusService)
	<-sigChan
	log.Printf("[NM-LagoFast] Shutting down service")
	s.Disconnect()
	return nil
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip4)
}

package nm

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/godbus/dbus/v5"
	"github.com/lagofast/lagofast-vpn/pkg/api"
	"github.com/lagofast/lagofast-vpn/pkg/model"
	"github.com/lagofast/lagofast-vpn/pkg/tunnel"
)

var DefaultGameCIDRs = map[int][]string{
	54758: { // Where Winds Meet (NetEase & Cloud Game Servers)
		"47.84.0.0/16",   // Alibaba Cloud Singapore (Where Winds Meet Server Cluster)
		"47.237.0.0/16",  // Alibaba Cloud Singapore Cluster
		"47.242.0.0/16",  // Alibaba Cloud Singapore
		"47.238.0.0/16",  // Alibaba Cloud Singapore
		"47.76.0.0/16",   // Alibaba Cloud Singapore
		"8.219.0.0/16",   // Alibaba Cloud Singapore Detection
		"43.245.0.0/16",  // NetEase Hong Kong / Singapore
		"119.28.0.0/16",  // Tencent / NetEase SEA Clusters
		"150.109.0.0/16", // NetEase Singapore Cluster
		"129.226.0.0/16", // Tencent / NetEase SEA
		"101.32.0.0/16",  // NetEase SEA Gaming
		"14.0.45.0/24",   // NetEase Tokyo Cluster
		"8.216.0.0/16",   // NetEase Japan Cluster
		"163.171.0.0/16", // NetEase Singapore / Japan
	},
}

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
	conn       *dbus.Conn
	state      uint32
	tunDev     *tunnel.Device
	apiClient  *api.Client
	session    *model.UserSession
	activeGame *model.GameItem
	activeNode *model.NodeItem
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

	log.Printf("[NM-LagoFast] Benchmarking lowest latency relay node for Game ID %d...", gameID)
	bestNode, rtt, nodeErr := s.apiClient.SelectOptimalNode(gameID)
	if nodeErr != nil {
		log.Printf("[NM-LagoFast] Node benchmark warning: %v", nodeErr)
	} else {
		s.activeNode = bestNode
		log.Printf("[NM-LagoFast] Selected optimal node: %s (%s:%d) [RTT: %v]", bestNode.NodeName, bestNode.NodeIP, bestNode.Port, rtt)
	}

	zoneID := 0
	if gameID == 54758 {
		zoneID = 45983 // Singapore zone
	}
	if zoneIDStr, ok := vpnData["zone_id"].Value().(string); ok && zoneIDStr != "" {
		if zid, err := strconv.Atoi(zoneIDStr); err == nil {
			zoneID = zid
		}
	}

	nodeIP := "43.153.212.197"
	nodePort := 9993
	if s.activeNode != nil {
		nodeIP = s.activeNode.NodeIP
		nodePort = s.activeNode.Port
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
	if bestNode.GroupID > 0 {
		groupIDStr = fmt.Sprintf("%d", bestNode.GroupID)
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
				"defaultOutTag": "proxy",
				"rules":         []interface{}{},
			},
		},
		"customProfile": map[string]interface{}{
			"qyproxy_config": map[string]interface{}{
				"game_area": zoneFlag,
			},
			"qyproxy_game_config": map[string]interface{}{
				"confuse":            7,
				"enableProxyModeDNS": false,
				"enableUdpTunnel":    true,
				"log_level":          "DEBUG",
				"nat_open":           false,
			},
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

	// Assemble Subnet / CIDR routes for game acceleration
	var routesList [][]uint32
	cidrs, hasCIDRs := DefaultGameCIDRs[gameID]
	if !hasCIDRs {
		cidrs = DefaultGameCIDRs[54758]
	}
	for _, cidr := range cidrs {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
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
		"external-ip4":  dbus.MakeVariant(ipToUint32(gatewayIP)),
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
	log.Printf("[NM-LagoFast] VPN connection established successfully (Game ID: %s)", gameIDStr)
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

	s.setState(StateStopped)
	log.Printf("[NM-LagoFast] Disconnected cleanly")
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

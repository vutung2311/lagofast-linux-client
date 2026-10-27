package nm

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

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

	// Create TUN interface
	tunDev, err := tunnel.OpenTun("lagofast0", 1400)
	if err != nil {
		log.Printf("[NM-LagoFast] Failed to create TUN: %v", err)
		s.emitFailure(ErrorDeviceFailed)
		return dbus.NewError("org.freedesktop.NetworkManager.VPN.Error.DeviceFailed", []interface{}{err.Error()})
	}
	s.tunDev = tunDev

	// Assign local IP
	localIP := net.ParseIP("10.200.0.2")
	gatewayIP := net.ParseIP("10.200.0.1")
	dnsIP := net.ParseIP("1.1.1.1")

	ip4Config := map[string]dbus.Variant{
		"tundev":     dbus.MakeVariant(tunDev.Name),
		"internal-ip4": dbus.MakeVariant(ipToUint32(localIP)),
		"external-ip4": dbus.MakeVariant(ipToUint32(gatewayIP)),
		"address":    dbus.MakeVariant(ipToUint32(localIP)),
		"prefix":     dbus.MakeVariant(uint32(24)),
		"gateway":    dbus.MakeVariant(ipToUint32(gatewayIP)),
		"dns":        dbus.MakeVariant([]uint32{ipToUint32(dnsIP)}),
		"mtu":        dbus.MakeVariant(uint32(1400)),
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

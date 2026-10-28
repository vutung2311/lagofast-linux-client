package model

// VpnConfigModel matches the JSON expected by QyProxy / LagoFast tunnel engine
type VpnConfigModel struct {
	Server        VpnConfigServer        `json:"server"`
	Client        VpnConfigClient        `json:"client"`
	GameInfo      VpnConfigGameInfo      `json:"gameinfo"`
	SNI           []string               `json:"SNI,omitempty"`
	DivertRuleset map[string]interface{} `json:"divertRuleset,omitempty"`
	MultiNetLink  *MultiNetLink          `json:"multiNetLink,omitempty"`
}

type VpnConfigServer struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type VpnConfigProductLine struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

type VpnConfigClient struct {
	Protocol             string               `json:"protocol"`
	GroupID              int                  `json:"groupId"`
	LoginToken           string               `json:"loginToken"`
	Username             string               `json:"username"`
	Password             string               `json:"password"`
	ClientType           int                  `json:"client_type"`
	EventID              int                  `json:"eventId"`
	SN                   string               `json:"sn"`
	Mode                 int                  `json:"mode"`
	ServerID             int                  `json:"serverid"`
	ProductLine          VpnConfigProductLine `json:"product_line"`
	EnableLwip           bool                 `json:"enableLwip"`
	EnableFineDivert     bool                 `json:"enableFineDivert"`
	UseMultiTunnel       bool                 `json:"useMultiTunnel"`
	NetworkReachablePort int                  `json:"networkReachablePort"`
	SelectZoneFlag       string               `json:"select_zone_flag,omitempty"`
	SessionSize          int                  `json:"sessionSize,omitempty"`
	EnableSpeedCounter   bool                 `json:"enableSpeedCounter"`
	PingFullLink         bool                 `json:"ping_full_link"`
	NetworkWay           string               `json:"network_way,omitempty"`
}

type VpnConfigGameInfo struct {
	GameID int `json:"game_id"`
}

type MultiNetLink struct {
	Enable      bool   `json:"enable"`
	NodeAddress string `json:"node_address,omitempty"`
}

// REST API models

type BaseResponse[T any] struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
	Data    T      `json:"data"`
}

type LoginRequest struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

type UserSession struct {
	UID         string `json:"uid"`
	Account     string `json:"account"`
	Token       string `json:"token"`
	Email       string `json:"email,omitempty"`
	Nickname    string `json:"nickname,omitempty"`
	ExpireTime  int64  `json:"expire_time,omitempty"`
	IsVIP       bool   `json:"is_vip,omitempty"`
	RemainHours int    `json:"remain_hours,omitempty"`
}

type GameItem struct {
	GameID   int    `json:"game_id"`
	GameName string `json:"game_name"`
	IconURL  string `json:"icon_url"`
	Package  string `json:"package_name,omitempty"`
	ZoneList []Zone `json:"zone_list,omitempty"`
}

type Zone struct {
	ZoneID   int    `json:"zone_id"`
	ZoneName string `json:"zone_name"`
}

type NodeItem struct {
	NodeID   int    `json:"node_id"`
	GroupID  int    `json:"group_id"`
	NodeName string `json:"node_name"`
	NodeIP   string `json:"node_ip"`
	Port     int    `json:"port"`
	PingMs   int    `json:"ping_ms,omitempty"`
	Country  string `json:"country,omitempty"`
}

type RouteConfig struct {
	GameID   int        `json:"game_id"`
	GameName string     `json:"game_name"`
	Nodes    []NodeItem `json:"nodes"`
	Routes   []string   `json:"routes"`
}

type AcctDetailAllResponse struct {
	AppNo          string                 `json:"app_no"`
	ClientType     int                    `json:"client_type"`
	AcctFlag       string                 `json:"acct_flag"`
	SelectAcctFlag string                 `json:"select_acct_flag"`
	Auth           AcctAuth               `json:"auth"`
	CustomConfig   map[string]interface{} `json:"custom_config"`
}

type AcctAuth struct {
	MemberID    string `json:"member_id"`
	AccountName string `json:"account_name"`
	AccountPwd  string `json:"account_pwd"`
}

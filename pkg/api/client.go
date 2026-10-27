package api

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lagofast/lagofast-vpn/pkg/model"
)

const (
	DefaultBaseURL = "https://cbs.lagofast.com"
	UserAgent      = "Pixel7/14/34/web_m/LagoFast-Mobile-Android/2.2.0.0/c7a544b6-7917-488b-b892-06b297b1028b/en"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Token      string
	Account    string
	UID        string
}

func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *Client) SetToken(token, uid string) {
	c.Token = token
	c.UID = uid
}

func (c *Client) doRequest(method, path string, query url.Values, body interface{}) ([]byte, error) {
	reqURL := c.BaseURL + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Client-Language", "en")
	req.Header.Set("Saas-App-Id", "LG_ANDROID")
	req.Header.Set("Saas-Product-Line", "LG")
	req.Header.Set("Saas-Platform", "android")
	if c.Token != "" {
		req.Header.Set("Login-Credential", c.Token)
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return respBytes, fmt.Errorf("http error %d: %s", resp.StatusCode, string(respBytes))
	}

	return respBytes, nil
}

// HashPassword generates MD5 hash if the API expects hashed password
func HashPassword(pwd string) string {
	h := md5.New()
	h.Write([]byte(pwd))
	return hex.EncodeToString(h.Sum(nil))
}

// Login authenticates with LagoFast / Qiyou backend
func (c *Client) Login(account, password string) (*model.UserSession, error) {
	body := map[string]interface{}{
		"account":  account,
		"password": HashPassword(password),
	}

	respBytes, err := c.doRequest(http.MethodPost, "/api/common_bll/v1/member/action/pwd_login", nil, body)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"msg"`
		Data    struct {
			Token      string `json:"token"`
			UID        string `json:"uid"`
			Account    string `json:"account"`
			Nickname   string `json:"nickname"`
			ExpireTime int64  `json:"expire_time"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse login response: %w", err)
	}

	if resp.Code != 0 && resp.Code != 200 {
		return nil, fmt.Errorf("login failed (code %d): %s", resp.Code, resp.Message)
	}

	session := &model.UserSession{
		UID:        resp.Data.UID,
		Account:    resp.Data.Account,
		Token:      resp.Data.Token,
		Nickname:   resp.Data.Nickname,
		ExpireTime: resp.Data.ExpireTime,
	}

	c.SetToken(session.Token, session.UID)
	c.Account = session.Account
	return session, nil
}

// LoginWithToken validates an existing Login-Credential token and fetches user details
func (c *Client) LoginWithToken(token string) (*model.UserSession, error) {
	c.SetToken(token, "")
	respBytes, err := c.doRequest(http.MethodGet, "/api/common_bll/v1/member/detail", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	var resp struct {
		Code       int    `json:"code"`
		Message    string `json:"msg"`
		UID        string `json:"uid"`
		Account    string `json:"account"`
		MemberName string `json:"member_name"`
		Nickname   string `json:"nickname"`
		Email      string `json:"email"`
		ExpireTime int64  `json:"expire_time"`
		IsVIP      bool   `json:"is_vip"`
		Data       struct {
			UID        string `json:"uid"`
			Account    string `json:"account"`
			MemberName string `json:"member_name"`
			Nickname   string `json:"nickname"`
			Email      string `json:"email"`
			ExpireTime int64  `json:"expire_time"`
			IsVIP      bool   `json:"is_vip"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBytes, &resp); err != nil {
		session := &model.UserSession{
			Token: token,
		}
		return session, nil
	}

	uid := resp.UID
	if uid == "" {
		uid = resp.Data.UID
	}
	email := resp.Email
	if email == "" {
		email = resp.Data.Email
	}
	account := resp.Account
	if account == "" {
		account = resp.MemberName
	}
	if account == "" {
		account = resp.Data.Account
	}
	if account == "" {
		account = resp.Data.MemberName
	}
	nickname := resp.Nickname
	if nickname == "" {
		nickname = resp.Data.Nickname
	}
	expireTime := resp.ExpireTime
	if expireTime == 0 {
		expireTime = resp.Data.ExpireTime
	}
	isVIP := resp.IsVIP || resp.Data.IsVIP

	session := &model.UserSession{
		UID:        uid,
		Account:    account,
		Email:      email,
		Token:      token,
		Nickname:   nickname,
		ExpireTime: expireTime,
		IsVIP:      isVIP,
	}
	c.SetToken(token, session.UID)
	c.Account = session.Account
	return session, nil
}

// LoginWithGoogle authenticates using a Google ID token JWT
func (c *Client) LoginWithGoogle(credential string) (*model.UserSession, error) {
	body := map[string]string{
		"credential": credential,
	}

	respBytes, err := c.doRequest(http.MethodPost, "/api/third_party_login/v1/member/google/jwt_login", nil, body)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool `json:"success"`
		Result  struct {
			LoginCredential string `json:"login_credential"`
			UID             string `json:"uid"`
			Account         string `json:"account"`
			Nickname        string `json:"nickname"`
			ExpireTime      int64  `json:"expire_time"`
		} `json:"result"`
		ErrorMsg string `json:"error_msg"`
	}

	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse google login response: %w", err)
	}

	token := resp.Result.LoginCredential
	if token == "" {
		return nil, fmt.Errorf("google login failed: %s", resp.ErrorMsg)
	}

	session := &model.UserSession{
		UID:        resp.Result.UID,
		Account:    resp.Result.Account,
		Token:      token,
		Nickname:   resp.Result.Nickname,
		ExpireTime: resp.Result.ExpireTime,
	}

	c.SetToken(session.Token, session.UID)
	c.Account = session.Account
	return session, nil
}

// GetGameList searches or lists available games
func (c *Client) GetGameList(keyword string) ([]model.GameItem, error) {
	q := url.Values{}
	path := "/api/common_bll/v1/games/mobile_game_list/search/by_keyword"
	if keyword == "" {
		keyword = "war"
	}
	q.Set("keyword", keyword)
	q.Set("app_type", "android")

	respBytes, err := c.doRequest(http.MethodGet, path, q, nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Games []struct {
			GameID   int    `json:"game_id"`
			EnName   string `json:"en_name"`
			CnName   string `json:"cn_name"`
			GameIcon string `json:"game_icon"`
			AppName  string `json:"app_name"`
		} `json:"games"`
	}

	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse game list: %w", err)
	}

	var games []model.GameItem
	for _, item := range resp.Games {
		name := item.EnName
		if name == "" {
			name = item.CnName
		}
		games = append(games, model.GameItem{
			GameID:   item.GameID,
			GameName: name,
			IconURL:  item.GameIcon,
			Package:  item.AppName,
		})
	}
	return games, nil
}

// GetGameNodes retrieves node acceleration endpoints for a game
func (c *Client) GetGameNodes(gameID int) ([]model.NodeItem, error) {
	// Query default zone first
	zonesToQuery := []int{0}
	if gameID == 54758 {
		// Where Winds Meet popular zones: SEA (45983), Japan (46143), HK (14140), US West (46543)
		zonesToQuery = append(zonesToQuery, 45983, 46143, 14140, 46543)
	}

	var allNodes []model.NodeItem
	seenNodes := make(map[int]bool)
	var fetchErr error

	for _, zoneID := range zonesToQuery {
		q := url.Values{}
		q.Set("app_no", fmt.Sprintf("%d", gameID))
		q.Set("accelerate_object_no", fmt.Sprintf("%d", zoneID))
		q.Set("client_type", "20")

		respBytes, err := c.doRequest(http.MethodGet, "/api/accelerate_bff/v2/acct_object/node", q, nil)
		if err != nil {
			fetchErr = err
			continue
		}

		var resp struct {
			NodeMap map[string][]struct {
				NodeNo          int    `json:"node_no"`
				NodeName        string `json:"node_name"`
				PublicIP        string `json:"public_ip"`
				SupportProtocol string `json:"support_protocol"`
				PingPorts       []int  `json:"ping_ports"`
			} `json:"node_map"`
		}

		if err := json.Unmarshal(respBytes, &resp); err != nil {
			fetchErr = fmt.Errorf("failed to parse node json: %w", err)
			continue
		}

		for zoneName, nodeList := range resp.NodeMap {
			for _, n := range nodeList {
				if seenNodes[n.NodeNo] {
					continue
				}
				seenNodes[n.NodeNo] = true

				port := 9993
				if len(n.PingPorts) > 0 {
					port = n.PingPorts[0]
				}

				allNodes = append(allNodes, model.NodeItem{
					NodeID:   n.NodeNo,
					NodeName: n.NodeName,
					NodeIP:   n.PublicIP,
					Port:     port,
					Country:  strings.ToUpper(zoneName),
				})
			}
		}
	}

	if len(allNodes) == 0 && fetchErr != nil {
		return nil, fmt.Errorf("failed to retrieve game nodes: %w", fetchErr)
	}

	return allNodes, nil
}

// PingNode measures UDP echo round-trip time to a LagoFast relay node
func PingNode(ip string, port int, timeout time.Duration) (time.Duration, error) {
	if port <= 0 {
		port = 9993
	}
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	probe := []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	start := time.Now()
	_, err = conn.Write(probe)
	if err != nil {
		return 0, err
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	if n < 8 {
		return 0, fmt.Errorf("response too short: %d bytes", n)
	}

	rtt := time.Since(start)
	return rtt, nil
}

// SelectOptimalNode queries all candidate nodes for a game and selects the lowest RTT node via parallel UDP ping
func (c *Client) SelectOptimalNode(gameID int) (*model.NodeItem, time.Duration, error) {
	nodes, err := c.GetGameNodes(gameID)
	if err != nil {
		return nil, 0, err
	}
	if len(nodes) == 0 {
		return nil, 0, fmt.Errorf("no candidate nodes found for game %d", gameID)
	}

	type pingResult struct {
		node model.NodeItem
		rtt  time.Duration
		err  error
	}

	results := make(chan pingResult, len(nodes))
	var wg sync.WaitGroup

	// Concurrency limiter
	sem := make(chan struct{}, 20)

	for _, n := range nodes {
		wg.Add(1)
		go func(node model.NodeItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rtt, err := PingNode(node.NodeIP, node.Port, 600*time.Millisecond)
			results <- pingResult{node: node, rtt: rtt, err: err}
		}(n)
	}

	wg.Wait()
	close(results)

	var bestNode *model.NodeItem
	var bestRTT time.Duration = 999999 * time.Hour

	for res := range results {
		if res.err != nil {
			continue
		}
		if res.rtt < bestRTT {
			bestRTT = res.rtt
			bestNodeCopy := res.node
			bestNode = &bestNodeCopy
		}
	}

	if bestNode == nil {
		// Fallback to first available node if UDP echo is filtered on all nodes
		first := nodes[0]
		return &first, 0, fmt.Errorf("all nodes timed out on UDP ping, falling back to %s (%s)", first.NodeName, first.NodeIP)
	}

	return bestNode, bestRTT, nil
}

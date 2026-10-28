package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lagofast/lagofast-vpn/pkg/api"
	"github.com/lagofast/lagofast-vpn/pkg/auth"
	"github.com/lagofast/lagofast-vpn/pkg/model"
	"github.com/lagofast/lagofast-vpn/pkg/nm"
	"github.com/lagofast/lagofast-vpn/pkg/tunnel"
)

func printUsage() {
	fmt.Println("LagoFast VPN Client for Linux")
	fmt.Println("\nUsage:")
	fmt.Println("  lagofast login --google                     Authenticate via Google OAuth in browser")
	fmt.Println("  lagofast login --from-browser               Import existing session from browser cookies")
	fmt.Println("  lagofast login --token <token>              Authenticate with web session token")
	fmt.Println("  lagofast login -u <account> -p <password>   Authenticate with account & password")
	fmt.Println("  lagofast games [-q <search>]                List supported games")
	fmt.Println("  lagofast nodes -g <game_id>                 List acceleration nodes for a game")
	fmt.Println("  lagofast connect -g <game_id> [-n <node>]   Start game acceleration tunnel")
	fmt.Println("  lagofast run <command> [args...]            Launch game process with traffic bound to lagofast0")
	fmt.Println("  lagofast status                             Display active session status")
	fmt.Println("  lagofast logout                             Clear saved credentials")
	fmt.Println("  lagofast nm-add [-g <game_id>] [-n <name>]  Add/update NetworkManager VPN profile")
	fmt.Println("  lagofast nm-install                         Install NetworkManager VPN plugin")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	client := api.NewClient("")
	session, _ := model.LoadSession()
	if session != nil {
		client.SetToken(session.Token, session.UID)
		client.Account = session.Account
	}

	command := os.Args[1]
	switch command {
	case "login":
		loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
		account := loginCmd.String("u", "", "Account username or email")
		password := loginCmd.String("p", "", "Account password")
		useGoogle := loginCmd.Bool("google", false, "Authenticate using Google OAuth in browser")
		fromBrowser := loginCmd.Bool("from-browser", false, "Import session from browser cookies")
		googleToken := loginCmd.String("google-token", "", "Authenticate directly with Google ID token")
		loginToken := loginCmd.String("token", "", "Authenticate with existing Login-Credential token")
		loginCmd.Parse(os.Args[2:])

		var sess *model.UserSession
		var err error

		if *fromBrowser {
			fmt.Println("Reading LagoFast session from browser cookies...")
			token, cookieErr := auth.ReadLagofastCookie("Login-Credential")
			if cookieErr != nil {
				fmt.Printf("Failed to read cookie: %v\n", cookieErr)
				return
			}
			fmt.Println("Validating session token with LagoFast CBS...")
			sess, err = client.LoginWithToken(token)
		} else if *useGoogle {
			// Check if already logged in in browser first
			token, _ := auth.ReadLagofastCookie("Login-Credential")
			if token != "" {
				fmt.Println("Existing browser session detected. Validating...")
				sess, err = client.LoginWithToken(token)
			}
			if sess == nil {
				loginURL := "https://www.lagofast.com/en/user/login/"
				fmt.Println("Opening LagoFast sign-in in browser window...")
				fmt.Printf("URL: %s\n", loginURL)
				cmd, launchErr := auth.LaunchBrowserWindow(loginURL)
				if launchErr != nil {
					fmt.Printf("Warning: Failed to launch browser automatically: %v\nPlease open the URL manually.\n", launchErr)
				}
				fmt.Println("Waiting for authentication in browser (Sign in with Google)...")
				ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
				defer cancel()
				token, err = auth.WatchForLoginCookie(ctx, 5*time.Minute)
				if cmd != nil && cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
				auth.CloseAuthWindow()
				if err != nil {
					fmt.Printf("Authentication failed or cancelled: %v\n", err)
					return
				}
				fmt.Println("Session token captured! Validating with LagoFast...")
				sess, err = client.LoginWithToken(token)
			}
		} else if *loginToken != "" {
			fmt.Println("Validating session token with LagoFast...")
			sess, err = client.LoginWithToken(*loginToken)
		} else if *googleToken != "" {
			fmt.Println("Authenticating with Google ID token...")
			sess, err = client.LoginWithGoogle(*googleToken)
		} else if *account != "" && *password != "" {
			fmt.Printf("Authenticating account %s with LagoFast...\n", *account)
			sess, err = client.Login(*account, *password)
		} else {
			fmt.Println("Error: specify either --google, --from-browser, --token <token>, or -u & -p.")
			return
		}

		if err != nil {
			fmt.Printf("Login failed: %v\n", err)
			return
		}

		if err := model.SaveSession(sess); err != nil {
			fmt.Printf("Failed to save session: %v\n", err)
			return
		}
		fmt.Printf("Successfully logged in! (UID: %s, Account: %s)\n", sess.UID, sess.Account)

	case "games":
		gamesCmd := flag.NewFlagSet("games", flag.ExitOnError)
		searchQuery := gamesCmd.String("q", "", "Search query for game")
		gamesCmd.Parse(os.Args[2:])

		fmt.Printf("Fetching game catalog (query: %q)...\n", *searchQuery)
		games, err := client.GetGameList(*searchQuery)
		if err != nil {
			fmt.Printf("Failed to get game list: %v\n", err)
			return
		}

		fmt.Printf("\n%-10s %-30s %s\n", "GAME ID", "NAME", "PACKAGE")
		fmt.Println("----------------------------------------------------------------------")
		for _, g := range games {
			fmt.Printf("%-10d %-30s %s\n", g.GameID, g.GameName, g.Package)
		}
		fmt.Printf("\nTotal: %d games\n", len(games))

	case "nodes":
		nodesCmd := flag.NewFlagSet("nodes", flag.ExitOnError)
		gameID := nodesCmd.Int("g", 0, "Game ID")
		nodesCmd.Parse(os.Args[2:])

		if *gameID == 0 {
			fmt.Println("Error: -g <game_id> is required.")
			return
		}

		fmt.Printf("Querying relay nodes for Game ID %d...\n", *gameID)
		nodes, err := client.GetGameNodes(*gameID)
		if err != nil {
			fmt.Printf("Failed to retrieve nodes: %v\n", err)
			return
		}

		fmt.Printf("\n%-8s %-25s %-18s %-6s %s\n", "NODE ID", "NAME", "IP", "PORT", "COUNTRY")
		fmt.Println("----------------------------------------------------------------------")
		for _, n := range nodes {
			fmt.Printf("%-8d %-25s %-18s %-6d %s\n", n.NodeID, n.NodeName, n.NodeIP, n.Port, n.Country)
		}

	case "connect":
		connCmd := flag.NewFlagSet("connect", flag.ExitOnError)
		gameID := connCmd.Int("g", 0, "Game ID")
		zoneIDFlag := connCmd.Int("z", 0, "Zone ID (optional)")
		nodeIP := connCmd.String("n", "", "Optional custom node IP")
		tunName := connCmd.String("i", "lagofast0", "TUN interface name")
		connCmd.Parse(os.Args[2:])

		if *gameID == 0 {
			fmt.Println("Error: -g <game_id> is required.")
			return
		}

		if session == nil || session.Token == "" {
			fmt.Println("Error: No active login session found. Please run 'lagofast login' first.")
			return
		}

		zoneID := *zoneIDFlag
		if zoneID == 0 && *gameID == 54758 {
			zoneID = 45983 // Singapore zone
		}

		nodePort := 9993
		if *nodeIP == "" {
			var bestNode *model.NodeItem
			var rtt time.Duration
			var nodeErr error

			if zoneID > 0 {
				fmt.Printf("Benchmarking lowest latency relay node for Game ID %d, Zone ID %d...\n", *gameID, zoneID)
				bestNode, rtt, nodeErr = client.SelectOptimalNodeForZone(*gameID, zoneID)
				if nodeErr != nil {
					fmt.Printf("Zone node benchmark warning: %v, falling back to global\n", nodeErr)
					bestNode, rtt, nodeErr = client.SelectOptimalNode(*gameID)
				}
			} else {
				fmt.Printf("Benchmarking lowest latency relay node for Game ID %d...\n", *gameID)
				bestNode, rtt, nodeErr = client.SelectOptimalNode(*gameID)
			}

			if nodeErr != nil {
				fmt.Printf("Node benchmark warning: %v\n", nodeErr)
			} else {
				*nodeIP = bestNode.NodeIP
				nodePort = bestNode.Port
				fmt.Printf("Selected optimal node: %s (%s:%d) [RTT: %v]\n", bestNode.NodeName, bestNode.NodeIP, bestNode.Port, rtt)
			}
		} else {
			fmt.Printf("Target relay node: %s\n", *nodeIP)
		}

		if *nodeIP == "" {
			*nodeIP = "43.153.212.197"
		}

		fmt.Printf("Fetching acceleration credentials for Game ID %d, Zone ID %d...\n", *gameID, zoneID)
		accountName := session.Account
		plainPwd := "tposwy"
		zoneFlag := "sg"

		acctDetail, detailErr := client.GetAcctDetailAll(*gameID, zoneID)
		if detailErr != nil {
			fmt.Printf("Warning: GetAcctDetailAll failed (%v), using default credentials\n", detailErr)
		} else {
			if acctDetail.Auth.AccountName != "" {
				accountName = acctDetail.Auth.AccountName
			}
			if acctDetail.SelectAcctFlag != "" {
				zoneFlag = acctDetail.SelectAcctFlag
			}
			decrypted, decErr := api.DecryptAcctPassword(session.UID, acctDetail.Auth.AccountPwd)
			if decErr != nil {
				fmt.Printf("Warning: DecryptAcctPassword failed (%v), fallback to default\n", decErr)
			} else if decrypted != "" {
				plainPwd = decrypted
			}
		}

		fmt.Printf("Initializing LagoFast tunnel on %s for Game ID %d...\n", *tunName, *gameID)
		dev, err := tunnel.OpenTun(*tunName, 1400)
		if err != nil {
			fmt.Printf("Failed to open TUN device: %v (Note: requires root/CAP_NET_ADMIN)\n", err)
			return
		}
		defer dev.Close()

		tunnelConfig := map[string]interface{}{
			"server": map[string]interface{}{
				"address": *nodeIP,
				"port":    nodePort,
			},
			"client": map[string]interface{}{
				"protocol":           "UDP",
				"group_id":           "320",
				"login_token":        session.Token,
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
				"tunId":              *tunName,
			},
			"gameinfo": map[string]interface{}{
				"game_id": *gameID,
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
		fmt.Printf("Initializing QyProxy tunnel engine...\n")
		if err := tunnel.DefaultEngine.Init(""); err != nil {
			fmt.Printf("Engine initialization failed: %v\n", err)
			return
		}
		fmt.Printf("Starting QyProxy tunnel engine...\n")
		if err := tunnel.DefaultEngine.Start(string(cfgBytes), int(dev.File.Fd())); err != nil {
			fmt.Printf("Failed to start QyProxy engine: %v\n", err)
			return
		}
		defer tunnel.DefaultEngine.Stop()

		localIP := net.ParseIP("10.10.10.2")
		mask := net.CIDRMask(24, 32)
		if err := dev.SetIP(localIP, mask); err != nil {
			fmt.Printf("Warning: failed to configure IP on %s: %v\n", dev.Name, err)
		}

		fmt.Printf("✓ QyProxy tunnel active on %s (IP: 10.10.10.2/24)\n", dev.Name)
		fmt.Println("LagoFast GPN connected. Press Ctrl+C to terminate.")

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Println("\nStopping tunnel...")

	case "status":
		if session == nil {
			fmt.Println("No active session found. Please run 'lagofast login'.")
			return
		}
		fmt.Printf("Logged in as: %s\n", session.Account)
		fmt.Printf("User UID:     %s\n", session.UID)
		if session.Nickname != "" {
			fmt.Printf("Nickname:     %s\n", session.Nickname)
		}
		if session.ExpireTime > 0 {
			fmt.Printf("Expires:      %d\n", session.ExpireTime)
		}

	case "logout":
		os.Remove(model.GetConfigPath())
		fmt.Println("Logged out successfully.")

	case "nm-add":
		nmAddCmd := flag.NewFlagSet("nm-add", flag.ExitOnError)
		gameID := nmAddCmd.Int("g", 54758, "Game ID")
		conName := nmAddCmd.String("n", "", "Connection name (default: LagoFast-WWM)")
		nmAddCmd.Parse(os.Args[2:])

		targetName := *conName
		if targetName == "" {
			if *gameID == 54758 {
				targetName = "LagoFast-WWM"
			} else {
				targetName = fmt.Sprintf("LagoFast-Game-%d", *gameID)
			}
		}

		fmt.Printf("Configuring NetworkManager connection '%s' (Game ID: %d)...\n", targetName, *gameID)
		vpnData := fmt.Sprintf("game_id=%d", *gameID)

		routeList, err := client.GetGameRoutingSubnets(*gameID, 0)
		if err != nil {
			routeList = nil
		}
		seenRoutes := make(map[string]bool)
		var combinedRoutes []string
		for _, r := range routeList {
			if !seenRoutes[r] {
				seenRoutes[r] = true
				combinedRoutes = append(combinedRoutes, r)
			}
		}
		for _, r := range nm.DefaultGameCIDRs[*gameID] {
			if !seenRoutes[r] {
				seenRoutes[r] = true
				combinedRoutes = append(combinedRoutes, r)
			}
		}
		gameRoutes := strings.Join(combinedRoutes, ", ")
		fmt.Printf("Configured %d routing subnets (dynamic + game cluster baseline).\n", len(combinedRoutes))

		checkCmd := exec.Command("nmcli", "connection", "show", targetName)
		if err := checkCmd.Run(); err != nil {
			addCmd := exec.Command("nmcli", "connection", "add", "type", "vpn", "vpn-type", "lagofast", "con-name", targetName, "vpn.data", vpnData, "ipv4.never-default", "yes", "ipv4.routes", gameRoutes, "connection.autoconnect", "no")
			if err := addCmd.Run(); err != nil {
				fmt.Printf("Failed to add connection: %v\n", err)
				return
			}
			fmt.Printf("✓ Successfully created connection '%s' in NetworkManager with game subnets.\n", targetName)
		} else {
			modCmd := exec.Command("nmcli", "connection", "modify", targetName, "vpn.data", vpnData, "ipv4.never-default", "yes", "ipv4.routes", gameRoutes, "connection.autoconnect", "no")
			if err := modCmd.Run(); err != nil {
				fmt.Printf("Failed to update connection: %v\n", err)
				return
			}
			fmt.Printf("✓ Updated existing NetworkManager connection '%s' with game subnets.\n", targetName)
		}
		fmt.Printf("You can now connect and disconnect from your desktop system tray, or via CLI:\n  nmcli connection up %q\n  nmcli connection down %q\n", targetName, targetName)

	case "run":
		if len(os.Args) < 3 {
			fmt.Println("Usage: lagofast run <command> [args...]")
			fmt.Println("\nAccelerates a specific game process by routing all its network traffic through lagofast0.")
			fmt.Println("\nExamples:")
			fmt.Println("  lagofast run wine WhereWindsMeet.exe")
			fmt.Println("  lagofast run steam steam://rungameid/54758")
			fmt.Printf("  Steam Launch Options: lagofast run %s\n", "%command%")
			return
		}

		// Check if lagofast0 is active
		_, ifaceErr := net.InterfaceByName("lagofast0")
		if ifaceErr != nil {
			fmt.Println("[LagoFast] Notice: 'lagofast0' interface is not active yet.")
			fmt.Println("           Connect via NetworkManager tray or 'nmcli connection up LagoFast-WWM'.")
			fmt.Println("           Launching process anyway; traffic will route through booster when active.")
		}

		targetBin, lookErr := exec.LookPath(os.Args[2])
		if lookErr != nil {
			fmt.Printf("Command not found: %s\n", os.Args[2])
			return
		}

		bindLib := "/usr/local/lib/liblagofast_bind.so"
		_, statErr := os.Stat(bindLib)
		if statErr != nil {
			abs, absErr := filepath.Abs("./bin/liblagofast_bind.so")
			if absErr != nil {
				abs = "./bin/liblagofast_bind.so"
			}
			bindLib = abs
		}

		env := os.Environ()
		existingPreload := os.Getenv("LD_PRELOAD")
		if existingPreload != "" {
			env = append(env, fmt.Sprintf("LD_PRELOAD=%s:%s", bindLib, existingPreload))
		} else {
			env = append(env, fmt.Sprintf("LD_PRELOAD=%s", bindLib))
		}
		env = append(env, "LAGOFAST_DEVICE=lagofast0")

		args := os.Args[2:]
		fmt.Printf("[LagoFast] Launching game process with bound tunnel 'lagofast0': %s\n", strings.Join(args, " "))
		execErr := syscall.Exec(targetBin, args, env)
		if execErr != nil {
			fmt.Printf("Failed to execute %s: %v\n", targetBin, execErr)
		}

	case "nm-install":
		installNetworkManagerPlugin()

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
	}
}

func installNetworkManagerPlugin() {
	serviceFileContent := `[VPN Connection]
name=lagofast
service=org.freedesktop.NetworkManager.lagofast
program=/usr/local/bin/nm-lagofast-service
supports-multiple-connections=false
`
	dbusPolicyContent := `<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.freedesktop.NetworkManager.lagofast"/>
    <allow send_destination="org.freedesktop.NetworkManager.lagofast"/>
  </policy>
  <policy context="default">
    <deny own="org.freedesktop.NetworkManager.lagofast"/>
    <allow send_destination="org.freedesktop.NetworkManager.lagofast"/>
  </policy>
</busconfig>
`
	fmt.Println("NetworkManager Plugin configuration:")
	fmt.Printf("\n1. Save to /etc/NetworkManager/VPN/nm-lagofast-service.name:\n%s\n", serviceFileContent)
	fmt.Printf("2. Save to /etc/dbus-1/system.d/nm-lagofast-service.conf:\n%s\n", dbusPolicyContent)
	fmt.Println("Run 'scripts/install-nm-plugin.sh' with pkexec to install automatically.")
}

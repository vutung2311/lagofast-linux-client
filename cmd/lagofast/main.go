package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/lagofast/lagofast-vpn/pkg/api"
	"github.com/lagofast/lagofast-vpn/pkg/auth"
	"github.com/lagofast/lagofast-vpn/pkg/model"
	"github.com/lagofast/lagofast-vpn/pkg/tunnel"
)

func printUsage() {
	fmt.Println("LagoFast VPN Client for Linux")
	fmt.Println("\nUsage:")
	fmt.Println("  lagofast login                              Sign in with Google in any browser (prints the URL too)")
	fmt.Println("  lagofast login --no-open                    Only print the sign-in URL, e.g. for another device")
	fmt.Println("  lagofast login --from-browser [--browser id] Fallback: import a session from browser cookies")
	fmt.Println("  lagofast login --list-browsers              Show detected browser profiles")
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
		_ = loginCmd.Bool("google", false, "Sign in with Google in any browser (the default)")
		noOpen := loginCmd.Bool("no-open", false, "Only print the sign-in URL (e.g. to open it on another device)")
		timeout := loginCmd.Duration("timeout", 5*time.Minute, "How long to wait for the sign-in to complete")
		fromBrowser := loginCmd.Bool("from-browser", false, "Fallback: import a session from Chromium browser cookies")
		googleToken := loginCmd.String("google-token", "", "Authenticate directly with Google ID token")
		loginToken := loginCmd.String("token", "", "Authenticate with existing Login-Credential token")
		browserPref := loginCmd.String("browser", os.Getenv("LAGOFAST_BROWSER"),
			`With --from-browser: profile to read, e.g. "chrome:Default", "chrome" or an email (env LAGOFAST_BROWSER)`)
		listBrowsers := loginCmd.Bool("list-browsers", false, "List detected browser profiles and exit")
		loginCmd.Parse(os.Args[2:])

		if *listBrowsers {
			printBrowserProfiles()
			return
		}

		var sess *model.UserSession
		var err error
		usedProfile := ""

		// validate checks a cookie token against LagoFast and keeps the session on success.
		validate := func(token string) error {
			s, verr := client.LoginWithToken(token)
			if verr != nil {
				return verr
			}
			sess = s
			return nil
		}

		if *fromBrowser {
			profiles := auth.DiscoverProfiles()
			if *browserPref != "" {
				profiles = auth.MatchProfiles(profiles, *browserPref)
				if len(profiles) == 0 {
					fmt.Printf("No browser profile matches %q. Run 'lagofast login --list-browsers'.\n", *browserPref)
					os.Exit(1)
				}
			}
			fmt.Println("Reading LagoFast session from browser cookies...")
			type found struct {
				p   auth.BrowserProfile
				tok string
				at  time.Time
			}
			var cands []found
			for _, p := range profiles {
				cookies, cerr := p.ReadLagofastCookies(auth.LoginCookieName)
				if cerr != nil {
					fmt.Printf("  %s: %v\n", p.Label(), cerr)
					continue
				}
				for _, c := range cookies {
					if c.Value != "" {
						cands = append(cands, found{p, c.Value, c.Created})
						break
					}
				}
			}
			if len(cands) == 0 {
				fmt.Println("No LagoFast login cookie found in any browser profile. Try plain 'lagofast login'.")
				os.Exit(1)
			}
			sort.Slice(cands, func(i, j int) bool { return cands[i].at.After(cands[j].at) })
			for _, c := range cands {
				fmt.Printf("Validating session from %s...\n", c.p.Label())
				if err = validate(c.tok); err == nil {
					usedProfile = c.p.ID()
					sess.LoginMethod = "browser-cookie"
					break
				}
				fmt.Printf("  rejected: %v\n", err)
			}
		} else if *loginToken != "" {
			fmt.Println("Validating session token with LagoFast...")
			if sess, err = client.LoginWithToken(*loginToken); err == nil {
				sess.LoginMethod = "token"
			}
		} else if *googleToken != "" {
			fmt.Println("Authenticating with Google ID token...")
			if sess, err = client.LoginWithGoogle(*googleToken); err == nil {
				sess.LoginMethod = "google-jwt"
			}
		} else if *account != "" || *password != "" {
			if *account == "" || *password == "" {
				fmt.Println("Error: -u and -p must be given together.")
				return
			}
			fmt.Printf("Authenticating account %s with LagoFast...\n", *account)
			if sess, err = client.Login(*account, *password); err == nil {
				sess.LoginMethod = "password"
			}
		} else {
			// Default: device-style Google sign-in that works in any browser.
			sess, err = deviceGoogleLogin(client, *noOpen, *timeout)
		}

		if err != nil || sess == nil {
			fmt.Printf("Login failed: %v\n", err)
			os.Exit(1)
		}
		sess.BrowserProfile = usedProfile

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
		dev, err := tunnel.OpenTun(*tunName, tunnel.DefaultMTU)
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
				"protocol":    "UDP",
				"group_id":    "320",
				"login_token": session.Token,
				"username":    accountName,
				"password":    plainPwd,
				"client_type": 20,
				"eventId":     12345678,
				"sn":          "c7a544b6-7917-488b-b892-06b297b1028b",
				"mode":        1,
				"serverid":    zoneID,
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
					"log_level":          tunnel.NativeLogLevel(),
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
			os.Exit(1)
		}
		// Ask the backend: the session file alone says nothing about whether
		// LagoFast still accepts the token. Every field printed below comes from
		// this live response; nothing is filled in from local guesses.
		live, verr := client.LoginWithToken(session.Token)
		if verr != nil {
			if api.IsUnauthorized(verr) {
				fmt.Printf("Session:      EXPIRED or revoked (account %s). Run 'lagofast login'.\n", session.Account)
				os.Exit(1)
			}
			fmt.Printf("Session:      UNKNOWN - could not reach LagoFast (%v)\n", verr)
			fmt.Printf("Saved for:    %s (UID %s), not verified now\n", session.Account, session.UID)
			os.Exit(2)
		}
		fmt.Println("Session:      valid (confirmed by LagoFast just now)")
		fmt.Printf("Logged in as: %s\n", live.Account)
		fmt.Printf("User UID:     %s\n", live.UID)
		if live.Email != "" && live.Email != live.Account {
			fmt.Printf("Email:        %s\n", live.Email)
		}
		if live.Nickname != "" {
			fmt.Printf("Nickname:     %s\n", live.Nickname)
		}
		if live.ExpireTime > 0 {
			fmt.Printf("Expires:      %s\n", time.Unix(live.ExpireTime, 0).Format(time.RFC3339))
		} else {
			fmt.Println("Expires:      not reported by LagoFast")
		}
		if live.IsVIP {
			fmt.Println("VIP:          yes")
		} else {
			fmt.Println("VIP:          not reported by LagoFast")
		}
		method := session.LoginMethod
		if method == "" {
			method = "unknown (saved before login methods were recorded)"
		}
		fmt.Printf("Signed in via: %s\n", method)
		if session.Verified && session.VerifiedAt > 0 {
			fmt.Printf("Backend-issued at: %s\n", time.Unix(session.VerifiedAt, 0).Format(time.RFC3339))
		}
		if live.UID != session.UID {
			fmt.Printf("Warning: saved UID %s differs from the server's %s; run 'lagofast login' again.\n", session.UID, live.UID)
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
		gameRoutes := strings.Join(combinedRoutes, ", ")
		fmt.Printf("Configured %d dynamic routing subnets from LagoFast REST API.\n", len(combinedRoutes))

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

func printBrowserProfiles() {
	profiles := auth.DiscoverProfiles()
	if len(profiles) == 0 {
		fmt.Println("No Chromium-based browser profiles found.")
		return
	}
	for _, p := range profiles {
		state := ""
		if tok, err := p.ReadLoginCredential(); err != nil {
			state = "  [cookies unreadable: " + err.Error() + "]"
		} else if tok != "" {
			state = "  [has LagoFast login cookie]"
		}
		fmt.Printf("  %-22s %s%s\n", p.ID(), p.Label(), state)
	}
	fmt.Println("\nOnly used by 'lagofast login --from-browser --browser <id>'.")
}

// deviceGoogleLogin runs the browser-independent Google sign-in: open (and print) a
// LagoFast URL bound to a fresh random state, then poll the backend until that
// state carries a session. No cookies, keyring or local callback server involved.
func deviceGoogleLogin(client *api.Client, noOpen bool, timeout time.Duration) (*model.UserSession, error) {
	state, err := api.NewLoginState()
	if err != nil {
		return nil, err
	}
	loginURL := api.GoogleLoginURL("", state)

	fmt.Println("Sign in to LagoFast with Google by opening this URL in any browser, on any device:")
	fmt.Printf("\n  %s\n\n", loginURL)
	if !noOpen && (os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "") {
		if cmd := exec.Command("xdg-open", loginURL); cmd.Start() == nil {
			go func() { _ = cmd.Wait() }()
			fmt.Println("(Opened in your default browser.)")
		} else {
			fmt.Println("(Could not run xdg-open; open the URL yourself.)")
		}
	}
	fmt.Printf("Waiting up to %s for sign-in to complete. Press Ctrl+C to cancel.\n", timeout)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()

	sess, err := client.PollGoogleLogin(ctx, state, api.PollOptions{
		OnPending: func(polls int, transient error) {
			if transient != nil {
				fmt.Printf("  still waiting (network problem, retrying: %v)\n", transient)
			} else if polls%10 == 0 {
				fmt.Println("  still waiting for sign-in...")
			}
		},
	})
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return nil, fmt.Errorf("timed out after %s waiting for sign-in", timeout)
	case errors.Is(err, context.Canceled):
		return nil, errors.New("cancelled")
	}
	return sess, err
}

//go:build windows

package main

import (
	"bufio"
	"embed" // Required for embedding files
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http" // Required for HTTP server
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket" // WebSocket library
	// Remove keybd_event import as it's not suitable for detection and is being removed
	// "github.com/micmonay/keybd_event"
)

// --- Embedded Files ---
//go:embed frontend/index.html
var embeddedFrontend embed.FS

// --- Constants ---
const (
	DEFAULT_HOST      = "127.0.0.1"
	DEFAULT_PORT      = "12345"
	LISTENER_TYPE     = "tcp"
	WEB_UI_ADDR       = "127.0.0.1:8080" // Address for the web UI HTTP server
	WEB_UI_URL        = "http://" + WEB_UI_ADDR
	CONFIG_FILE       = "config.json"
	LOG_FILE          = "listener_log.txt"
)

// --- Configuration ---
type Config struct {
	Host          string   `json:"host"`
	Port          string   `json:"port"`
	AllowCommands bool     `json:"allowCommands"` // Added from mockup
	AllowedIPs    []string `json:"allowedIPs"`    // Added from mockup
}

// --- Global State ---
var (
	// Listener State
	activeListener net.Listener
	listenerMutex  sync.Mutex // Protects activeListener and currentConfig related to listener
	currentConfig  Config     // Holds the currently active or last used config

	// Hotkey & UI - REMOVED HOTKEY VARIABLES
	// kb           keybd_event.KeyBonding // REMOVED
	// uiVisible    bool       // REMOVED (or repurpose if needed for web UI state)
	// uiMutexLocal sync.Mutex // REMOVED (or repurpose)


	// WebSocket Communication
	wsUpgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true }, // Allow all origins for simplicity
	}
	wsClients   = make(map[*websocket.Conn]bool) // Set of connected clients
	wsMutex     sync.RWMutex                     // Protects wsClients map
	broadcastCh = make(chan []byte, 100)         // Channel for broadcasting messages to clients
)

// --- Configuration Functions ---
// ... (loadConfig and saveConfig remain the same as the previous WebSocket version)
func loadConfig() Config {
	// Default config
	config := Config{
		Host:          DEFAULT_HOST,
		Port:          DEFAULT_PORT,
		AllowCommands: true, // Default value for new setting
		AllowedIPs:    []string{}, // Default empty list
	}

	data, err := os.ReadFile(CONFIG_FILE)
	if err == nil {
		// Make a temporary struct including only fields present in older config files
		// to avoid unmarshal errors if new fields are missing.
		var loadedData map[string]interface{}
		err = json.Unmarshal(data, &loadedData)
		if err != nil {
			log.Printf("Error unmarshalling config into map: %v. Using defaults.", err)
			return config // Return default on error
		}

		// Populate the config struct carefully, using defaults if fields are missing
		if host, ok := loadedData["host"].(string); ok && host != "" {
			config.Host = host
		}
		if port, ok := loadedData["port"].(string); ok && port != "" {
			config.Port = port
		}
		// Check for new fields, use defaults if not present or wrong type
		if allow, ok := loadedData["allowCommands"].(bool); ok {
			config.AllowCommands = allow
		}
		if ips, ok := loadedData["allowedIPs"].([]interface{}); ok {
			config.AllowedIPs = make([]string, 0, len(ips)) // Initialize slice
			for _, ipIntf := range ips {
				if ipStr, okStr := ipIntf.(string); okStr && ipStr != "" { // Check type and non-empty
					config.AllowedIPs = append(config.AllowedIPs, ipStr)
				}
			}
		}

	} else if !os.IsNotExist(err) {
		log.Printf("Error reading config file '%s': %v. Using defaults.", CONFIG_FILE, err)
	}

	// Ensure essential defaults if still empty after load attempt
	if config.Host == "" {
		config.Host = DEFAULT_HOST
	}
	if config.Port == "" {
		config.Port = DEFAULT_PORT
	}

	log.Printf("Loaded configuration: %+v", config)
	return config
}

func saveConfig(configToSave Config) {
	listenerMutex.Lock() // Protect access to currentConfig if saving it
	confToSave := configToSave
	listenerMutex.Unlock()

	log.Printf("Saving configuration: %+v", confToSave)
	data, err := json.MarshalIndent(confToSave, "", "  ")
	if err != nil {
		logMessage(fmt.Sprintf("Error marshalling config for saving: %v", err)) // Use logMessage for UI feedback
		return
	}
	err = os.WriteFile(CONFIG_FILE, data, 0644)
	if err != nil {
		logMessage(fmt.Sprintf("Error saving config file '%s': %v", CONFIG_FILE, err))
	} else {
		logMessage(fmt.Sprintf("Configuration saved to %s.", CONFIG_FILE))
	}
}

// --- Core Listener Logic ---

// ... (executeCommand, changeDirectory, getSysInfo remain the same)
func executeCommand(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error executing command '%s': %v\nOutput:\n%s", command, err, string(output))
	}
	return string(output)
}

func changeDirectory(path string) string {
	path = strings.Trim(path, "\" ")
	err := os.Chdir(path)
	if err != nil {
		return fmt.Sprintf("Error changing directory to '%s': %v", path, err)
	}
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf("Changed directory, but error getting current path: %v", err)
	}
	return fmt.Sprintf("Changed directory to: %s", wd)
}

func getSysInfo() string {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	hostname, hostErr := os.Hostname()
	if hostErr != nil {
		hostname = "N/A (" + hostErr.Error() + ")"
	}

	currentUser, userErr := user.Current()
	username := "N/A"
	if userErr == nil {
		username = currentUser.Username
	} else {
		username = "N/A (" + userErr.Error() + ")"
	}

	return fmt.Sprintf("OS: %s\nArchitecture: %s\nHostname: %s\nUsername: %s", osName, arch, hostname, username)
}


func handleConnection(conn net.Conn, cfg Config) { // Pass config for checks
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	// FIX: Assign remoteIP to _ since it's currently unused. Or comment out the line.
	// remoteIP, _, _ := net.SplitHostPort(remoteAddr)
	clientIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		logMessage(fmt.Sprintf("Error parsing remote address %s: %v", remoteAddr, err))
		return // Cannot perform IP check if address is invalid
	}


	// --- Enforce AllowedIPs ---
	if len(cfg.AllowedIPs) > 0 {
		allowed := false
		for _, allowedIP := range cfg.AllowedIPs {
			// TODO: Consider CIDR or range support if needed. For now, exact match.
			if clientIP == allowedIP {
				allowed = true
				break
			}
		}
		if !allowed {
			logMessage(fmt.Sprintf("Connection from %s rejected (IP %s not in allowed list: %v).", remoteAddr, clientIP, cfg.AllowedIPs))
			// Optionally inform the client
			// conn.Write([]byte("Connection rejected: Your IP is not allowed.\n"))
			return // Close the connection by returning
		}
	}

	logMessage(fmt.Sprintf("Client connected: %s", remoteAddr))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		command, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				logMessage(fmt.Sprintf("Error reading command from %s: %v", remoteAddr, err))
			}
			break
		}
		command = strings.TrimSpace(command)

		if command == "quit" {
			break
		}

		var result string
		isExecutionCmd := false // Flag command types that need checking against AllowCommands

		if strings.HasPrefix(command, "cd ") {
            isExecutionCmd = true
			path := strings.TrimSpace(strings.TrimPrefix(command, "cd "))
			if path == "" {
				result = "Usage: cd <directory>"
			} else {
				result = changeDirectory(path)
			}
		} else if command == "sysinfo" {
			isExecutionCmd = true // Count sysinfo as needing the allow flag too
			result = getSysInfo()
		} else if command != "" {
			isExecutionCmd = true
			result = executeCommand(command)
		} else {
			continue // Ignore empty commands
		}

        // --- Enforce AllowCommands ---
        if isExecutionCmd && !cfg.AllowCommands {
            logMessage(fmt.Sprintf("Command '%s' from %s blocked (AllowCommands is false).", command, remoteAddr))
            result = "Error: Command execution is disabled by configuration."
            // Prevent execution result from being sent by setting it to the error
        } else if isExecutionCmd {
             logMessage(fmt.Sprintf("Executing command '%s' from %s", command, remoteAddr))
        }


		_, err = writer.WriteString(result + "\n")
		if err != nil {
			break
		}
		err = writer.Flush()
		if err != nil {
			break
		}
	}
	logMessage(fmt.Sprintf("Client disconnected: %s", remoteAddr))
}

// ... (runListenerService, startListener, stopListenerService remain the same as WebSocket version)
// runListenerService now implicitly uses the passed 'serviceConfig' in calls to handleConnection
func runListenerService(ln net.Listener, stopChan chan struct{}, serviceConfig Config) {
	defer func() {
		listenerMutex.Lock()
		// Clean up only if this specific listener instance is still the active one
		if activeListener == ln {
			ln.Close()
			activeListener = nil
			logMessage("Listener service stopped and cleaned up.")
			broadcastStatus() // Inform UI listener has stopped
		} else {
			ln.Close() // Close this instance anyway
			logMessage("Old listener instance stopped.")
		}
		listenerMutex.Unlock()
	}()

	// Log the *effective* settings for this listener instance
	logMessage(fmt.Sprintf("Listener accepting connections on %s (AllowCommands: %v, AllowedIPs: %v)",
		ln.Addr(), serviceConfig.AllowCommands, serviceConfig.AllowedIPs))
	broadcastStatus() // Inform UI listener has started with specific config

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stopChan:
				logMessage("Listener stopping gracefully.")
				return // Exit loop
			default:
				if opErr, ok := err.(*net.OpError); ok && strings.Contains(opErr.Err.Error(), "use of closed network connection") {
					logMessage("Listener closed, accept loop ending.")
				} else {
					// Avoid spamming logs if listener is closed unexpectedly, check if still active
					listenerMutex.Lock()
					isActive := activeListener == ln
					listenerMutex.Unlock()
					if isActive {
						logMessage(fmt.Sprintf("Error accepting connection: %v", err))
					}
				}
				return // Exit loop on error or closure
			}
		}
		// Pass the config used when *starting* this listener instance to the handler
		go handleConnection(conn, serviceConfig)
	}
}

// Starts the listener if not already running. Uses the provided config.
func startListener(configToUse Config) error {
	listenerMutex.Lock()
	defer listenerMutex.Unlock()

	if activeListener != nil {
		msg := fmt.Sprintf("Listener is already running on %s", activeListener.Addr())
		logMessage(msg)
		// Also inform UI about failure
		broadcastError(nil, msg) // Send to all clients
		return fmt.Errorf(msg) // Return error to indicate it wasn't started now
	}

	addr := net.JoinHostPort(configToUse.Host, configToUse.Port)
	ln, err := net.Listen(LISTENER_TYPE, addr)
	if err != nil {
		errMsg := fmt.Sprintf("Error listening on %s: %v", addr, err)
		logMessage(errMsg)
		broadcastError(nil, errMsg) // Inform UI about the error
		return err                  // Return the error
	}

	activeListener = ln
	currentConfig = configToUse // Update global config state reflecting the running listener
	stopChan := make(chan struct{})

	// Start the accept loop goroutine, passing the specific config and stop channel
	// Use the *configToUse* for this specific listener instance
	go runListenerService(ln, stopChan, configToUse)

	// We need a way to signal this specific goroutine to stop. Closing the listener works.
	// Storing the stopChan per listener instance gets complicated if multiple could exist (though shouldn't here).
	// Relying on ln.Close() to signal the goroutine via Accept error is robust.

	logMessage(fmt.Sprintf("Listener service starting on %s...", addr))
	// Config is saved by the caller (e.g., WebSocket handler) *after* startListener succeeds
	return nil // Success
}


// Stops the currently active listener.
func stopListenerService() error {
	listenerMutex.Lock()
	// Capture listener instance while holding the lock
    lnToStop := activeListener
    listenerMutex.Unlock() // Release lock early, Close can block

	if lnToStop == nil {
		logMessage("Listener service is not running.")
		return nil // Not an error, just wasn't running
	}

	logMessage("Stopping listener service...")

    // Close the listener. This causes Accept() in the runListenerService goroutine to error out.
	err := lnToStop.Close()

	// Wait briefly to allow the runListenerService goroutine to process the closure and update state
    // This is a bit of a race condition fix, ideally runListenerService signals completion.
    // time.Sleep(50 * time.Millisecond)

	// Update the global state *after* initiating the close
	listenerMutex.Lock()
    // Verify it's still the same listener we intended to stop before nil-ing activeListener
    if activeListener == lnToStop {
        activeListener = nil // Mark as stopped
		broadcastStatus() // Explicitly broadcast stop here AFTER state update
    } else {
         logMessage("Listener state changed during stop operation, another listener might be active.")
    }
	listenerMutex.Unlock()


	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
        errMsg := fmt.Sprintf("Error closing listener: %v", err)
		logMessage(errMsg)
        broadcastError(nil, errMsg) // Inform UI
		return err // Return the error
	}

	logMessage("Listener stop initiated.")
	return nil       // Success
}


// --- Logging & Broadcasting ---
// ... (logMessage, broadcastStatus, broadcastError, handleBroadcasts remain the same)
func logMessage(message string) {
	timestamp := time.Now().Format("15:04:05") // Shorter timestamp for UI
	logEntry := fmt.Sprintf("[%s] %s", timestamp, message)

	// Log to console/file
	log.Println(logEntry) // Use the full entry for file log

	// Prepare message for WebSocket clients
	msgPayload := map[string]interface{}{
		"type":    "log",
		"message": logEntry, // Send the full log entry to UI
	}
	jsonData, err := json.Marshal(msgPayload)
	if err != nil {
		log.Printf("Error marshalling log message for broadcast: %v", err)
		return
	}

	// Send to broadcast channel (non-blocking)
	select {
	case broadcastCh <- jsonData:
	default:
		log.Println("Warning: Broadcast channel full. Log message dropped for UI.")
	}
}

// broadcastStatus sends the current listener status and config to all clients.
func broadcastStatus() {
	listenerMutex.Lock()
	status := activeListener != nil
	configToSend := currentConfig // Send the *active* or last known config
	listenerAddr := ""
	if activeListener != nil {
		listenerAddr = activeListener.Addr().String()
		// Update configToSend based on actual listener address if needed? Careful with "0.0.0.0"
		host, port, _ := net.SplitHostPort(listenerAddr)
		if configToSend.Host != host || configToSend.Port != port {
			 //log.Printf("Listener address %s differs from config %s:%s. Broadcasting actual.", listenerAddr, configToSend.Host, configToSend.Port)
			 // If you want UI to reflect the *exact* bound address:
			 // configToSend.Host = host
			 // configToSend.Port = port
		}
	}
	listenerMutex.Unlock()

	msgPayload := map[string]interface{}{
		"type":      "status",
		"listening": status,
		"address": listenerAddr, // Send actual listening address too
		"config":    configToSend,
	}
	jsonData, err := json.Marshal(msgPayload)
	if err != nil {
		log.Printf("Error marshalling status message for broadcast: %v", err)
		return
	}

	// Send to broadcast channel
	select {
	case broadcastCh <- jsonData:
	default:
		log.Println("Warning: Broadcast channel full. Status message dropped.")
	}
}

// broadcastError sends an error message to a specific client or all clients
func broadcastError(conn *websocket.Conn, message string) {
	msgPayload := map[string]interface{}{
		"type":    "error",
		"message": message,
	}
	jsonData, err := json.Marshal(msgPayload)
	if err != nil {
		log.Printf("Error marshalling error message for broadcast: %v", err)
		return
	}

	if conn != nil {
		// Send to specific client thread-safely
		err := writeToWsClient(conn, jsonData)
		if err != nil {
			log.Printf("Error sending error message to specific client %s: %v", conn.RemoteAddr(), err)
			removeWsClient(conn) // Remove if sending failed
		}
	} else {
		// Send to all clients via broadcast channel
		select {
		case broadcastCh <- jsonData:
		default:
			log.Println("Warning: Broadcast channel full. Error message dropped.")
		}
	}
}


// Manages broadcasting messages from broadcastCh to all connected clients.
func handleBroadcasts() {
	for message := range broadcastCh {
		wsMutex.RLock()
		// Create a list of clients to send to (avoids holding lock while sending)
		clientsToSend := make([]*websocket.Conn, 0, len(wsClients))
		for client := range wsClients {
			clientsToSend = append(clientsToSend, client)
		}
		wsMutex.RUnlock()

		for _, client := range clientsToSend {
			err := writeToWsClient(client, message) // Use helper for thread safety? (Not strictly needed here)
			if err != nil {
				log.Printf("Broadcast Error: removing client %s due to write error: %v", client.RemoteAddr(), err)
				removeWsClient(client) // Use helper for removal
			}
		}
	}
}

// Helper function to write to a websocket connection (can add mutex if needed)
func writeToWsClient(conn *websocket.Conn, message []byte) error {
	// wsMutex.Lock() // May need lock/unlock around conn.WriteMessage if concurrent writes possible *to the same conn*
	err := conn.WriteMessage(websocket.TextMessage, message)
	// wsMutex.Unlock()
	return err
}

// Helper function to remove a websocket client safely
func removeWsClient(conn *websocket.Conn) {
    wsMutex.Lock()
    if _, ok := wsClients[conn]; ok {
		delete(wsClients, conn)
		log.Printf("WebSocket client removed: %s (%d clients remaining)", conn.RemoteAddr(), len(wsClients))
        conn.Close() // Ensure connection is closed
    }
	wsMutex.Unlock()
}

// --- WebSocket Handler ---
// ... (wsHandler remains mostly the same, ensures config is passed/used correctly)
func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading WebSocket connection: %v", err)
		return
	}
	// Note: We don't defer conn.Close() here because removeWsClient handles it

	// Register new client
	wsMutex.Lock()
	wsClients[conn] = true
	log.Printf("WebSocket client connected: %s (%d clients)", conn.RemoteAddr(), len(wsClients))
	wsMutex.Unlock()

	// --- Send initial status immediately to the new client ---
	listenerMutex.Lock()
	status := activeListener != nil
	configToSend := currentConfig
	listenerAddr := ""
	if activeListener != nil {
		listenerAddr = activeListener.Addr().String()
	}
	listenerMutex.Unlock()

	initialPayload := map[string]interface{}{
		"type":      "status",
		"listening": status,
		"address":   listenerAddr,
		"config":    configToSend,
		"initial":   true, // Mark as initial status
	}
	initialJson, _ := json.Marshal(initialPayload)
	err = writeToWsClient(conn, initialJson) // Use helper
	if err != nil {
		log.Printf("Error sending initial status to client %s: %v", conn.RemoteAddr(), err)
		removeWsClient(conn) // Unregister client if initial send fails
		return              // Exit handler
	}
	// --- End Initial Status ---


	// Handle incoming messages from this client
	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure, websocket.CloseAbnormalClosure) {
				// Log unexpected errors
				log.Printf("Error reading WebSocket message from %s: %v", conn.RemoteAddr(), err)
			}
			break // Exit loop on read error or normal closure
		}

		if messageType == websocket.TextMessage {
			// Process the message
			var msg map[string]interface{}
			if err := json.Unmarshal(p, &msg); err != nil {
				log.Printf("Error unmarshalling message from %s: %v", conn.RemoteAddr(), err)
				broadcastError(conn, fmt.Sprintf("Invalid message format: %v", err))
				continue
			}

			// log.Printf("Received message from %s: %v", conn.RemoteAddr(), msg) // Can be noisy

			action, _ := msg["action"].(string)
			switch action {
			case "start":
				configData, ok := msg["config"].(map[string]interface{})
				if !ok {
					errMsg := fmt.Sprintf("Invalid 'start' message format from %s: missing or invalid config.", conn.RemoteAddr())
					logMessage(errMsg)
					broadcastError(conn, errMsg)
					continue
				}

				configJSON, _ := json.Marshal(configData)
				var requestedConfig Config
				// Reset to defaults before unmarshalling to avoid merging issues
				requestedConfig = Config{AllowCommands: true, AllowedIPs: []string{}}
				if err := json.Unmarshal(configJSON, &requestedConfig); err != nil {
					errMsg := fmt.Sprintf("Error unmarshalling requested config from %s: %v", conn.RemoteAddr(), err)
					logMessage(errMsg)
					broadcastError(conn, errMsg)
					continue
				}

				if requestedConfig.Host == "" || requestedConfig.Port == "" {
					errMsg := fmt.Sprintf("Invalid config from %s: Host or Port empty.", conn.RemoteAddr())
					logMessage(errMsg)
					broadcastError(conn, errMsg)
					continue
				}

				// Attempt to start the listener with the requested config
				err := startListener(requestedConfig)
				if err == nil {
					// Save the config *only if* the listener started successfully
					saveConfig(requestedConfig)
				}
				// Status update is broadcast by startListener/runListenerService or startListener error handling

			case "stop":
				_ = stopListenerService() // Error is logged and broadcast by stopListenerService
				// Status update is broadcast by stopListenerService/runListenerService

			case "get_status":
				// Send current status back to just this client
				listenerMutex.Lock()
				status := activeListener != nil
				configToSend := currentConfig
				listenerAddr := ""
				if activeListener != nil {
					listenerAddr = activeListener.Addr().String()
				}
				listenerMutex.Unlock()

				statusPayload := map[string]interface{}{
					"type":      "status",
					"listening": status,
					"address":   listenerAddr,
					"config":    configToSend,
				}
				statusJson, _ := json.Marshal(statusPayload)
				err = writeToWsClient(conn, statusJson)
				if err != nil {
					log.Printf("Error sending status to client %s: %v", conn.RemoteAddr(), err)
					// No need to remove client here, let the read loop detect failure
				}

			default:
				errMsg := fmt.Sprintf("Unknown action '%s' from %s", action, conn.RemoteAddr())
				logMessage(errMsg)
				broadcastError(conn, errMsg)
			}
		}
	}

	// Unregister client when loop exits
	removeWsClient(conn)
}


// --- HTTP Server ---
// ... (serveFrontend remains the same)
func serveFrontend(w http.ResponseWriter, r *http.Request) {
	content, err := embeddedFrontend.ReadFile("frontend/index.html")
	if err != nil {
		log.Printf("Error reading embedded index.html: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}


// --- Main Application Logic ---

func main() {
	// Ensure this runs only on Windows
	if runtime.GOOS != "windows" {
		fmt.Println("This application requires Windows.")
		log.Fatal("Runtime OS is not Windows.")
		return
	}

	// Setup logging
	logFile, logErr := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if logErr == nil {
		log.SetOutput(io.MultiWriter(os.Stdout, logFile))
		defer logFile.Close()
	} else {
		log.Println("Warning: Could not open log file:", logErr)
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("-------------------- Application Starting --------------------")

	// Load initial configuration
	currentConfig = loadConfig() // Load into global state

	// --- REMOVED Hotkey Initialization ---
	// var err error
	// kb, err = keybd_event.NewKeyBonding()
	// if err != nil {
	// 	log.Fatal("Fatal Error: Creating keybd instance failed:", err)
	// }
	// runtime.LockOSThread() // Not needed without keybd polling
	// defer runtime.UnlockOSThread()


	// --- Start HTTP Server for Web UI ---
	http.HandleFunc("/", serveFrontend) // Serve index.html at root
	http.HandleFunc("/ws", wsHandler)   // Handle WebSocket connections at /ws

	go func() {
		log.Printf("Starting Web UI server on %s", WEB_UI_ADDR)
		if err := http.ListenAndServe(WEB_UI_ADDR, nil); err != nil {
			// Use log.Printf for non-fatal startup issues if desired, Fatalf will exit
			log.Fatalf("Fatal Error: Failed to start Web UI server: %v", err)
		}
	}()

	// --- Start Broadcasting Goroutine ---
	go handleBroadcasts()

	// --- Optionally start listener on launch ---
	// Decided earlier to *not* auto-start. User uses UI.
	log.Println("Listener is initially stopped. Use the Web UI to start.")
	// broadcastStatus() // Broadcast initial status might be redundant as new clients get it

	// --- REMOVED Hotkey Goroutine ---
	/*
	ctx, cancel := context.WithCancel(context.Background()) // Context not needed if no background tasks like hotkey
	defer cancel()

	go func() { ... hotkey logic removed ... }()
	*/

	log.Printf("Initialization complete. Web UI available at %s", WEB_UI_URL)
	log.Println("Open the Web UI in your browser to control the listener.")


	// Keep the main goroutine alive
	select {} // Block forever
}
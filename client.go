package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

func main() {
	// --- Argument Parsing ---
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <server_ip> <server_port>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s 127.0.0.1 12345\n", os.Args[0])
		os.Exit(1)
	}
	serverIP := os.Args[1]
	serverPort := os.Args[2]
	serverAddr := net.JoinHostPort(serverIP, serverPort)

	// --- Connect to Server ---
	fmt.Printf("Connecting to %s...\n", serverAddr)
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to server: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("Connected.")

	// Channel to signal when server reading is done (due to error or EOF)
	done := make(chan struct{})

	// --- Goroutine to Read Server Responses ---
	go func() {
		defer close(done) // Signal main goroutine when this one exits
		serverReader := bufio.NewReader(conn)
		for {
			response, err := serverReader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					fmt.Println("\nServer closed the connection.")
				} else {
					// Check if it's a "use of closed network connection" error, which happens
					// when the main routine closes the connection after 'quit'. Don't print ugly error then.
					if !strings.Contains(err.Error(), "use of closed network connection") {
						fmt.Printf("\nError reading from server: %v\n", err)
					}
				}
				return // Exit goroutine
			}
			// Print the response exactly as received (server already adds newline)
			fmt.Print(response)
			// Print prompt again ONLY IF server sends output (to avoid double prompts)
            // We cannot reliably know if the server sent something AND finished,
            // so we rely on the main loop to print the next prompt.
		}
	}()

	// --- Main Loop to Read User Input ---
	userInputReader := bufio.NewReader(os.Stdin)
	fmt.Print("> ") // Initial prompt

	for {
		select {
		case <-done:
			// Server reading goroutine finished (error or disconnect)
			fmt.Println("Exiting due to server connection issue.")
			return // Exit main
		default:
			// Non-blocking check for 'done', proceed to read input if not done
		}

		command, err := userInputReader.ReadString('\n')
		if err != nil {
			// Handle potential error reading user input (e.g., Ctrl+D)
			fmt.Printf("\nError reading input: %v\n", err)
			return // Exit if we can't read input anymore
		}
		command = strings.TrimSpace(command)

		// Send command to server
		_, err = fmt.Fprintf(conn, "%s\n", command) // Ensure newline is sent
		if err != nil {
			fmt.Printf("Error sending command: %v\n", err)
			return // Exit if we can't write
		}

		// Handle 'quit' command locally
		if command == "quit" {
			fmt.Println("Disconnecting...")
			// The deferred conn.Close() will execute upon returning from main
			return
		}

		// Wait briefly for output from the server goroutine OR for user input again.
        // Printing the prompt here can lead to double prompts if server output arrives quickly.
        // Only print prompt after sending non-quit command IF the server connection is still presumed open.
		fmt.Print("> ") // Print next prompt
	}
}
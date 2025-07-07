package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Protocol version compliance
const MCP_PROTOCOL_VERSION = "2025-03-26"

// ServerConfig represents a single server configuration in the JSON file
type ServerConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Token   string   `json:"token,omitempty"` // Optional field for explicit token storage
}

// Config represents the full JSON configuration
type Config struct {
	MCPServers map[string]ServerConfig `json:"mcpServers"`
}

// loadConfig reads the MCP configuration from ~/.mcp/config.json
func loadConfig() (Config, error) {
	var config Config
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return config, fmt.Errorf("failed to get home directory: %w", err)
	}
	configPath := filepath.Join(homeDir, ".mcp", "config.json")
	fmt.Printf("DEBUG: Looking for config file at %s\n", configPath) // Temporary debug
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("DEBUG: Config file does not exist")
			return config, nil // Return empty config if file doesn't exist
		}
		return config, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to parse config file %s: %w", configPath, err)
	}
	fmt.Println("DEBUG: Config loaded successfully")
	return config, nil
}

// extractTokenFromArgs extracts a Bearer token from args if present
func extractTokenFromArgs(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--header" && strings.HasPrefix(args[i+1], "Authorization: Bearer ") {
			return strings.TrimPrefix(args[i+1], "Authorization: Bearer ")
		}
	}
	return ""
}

// JSONRPCMessage represents a JSON-RPC 2.0 message
type JSONRPCMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Method  string      `json:"method,omitempty"`
	Params  interface{} `json:"params,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError represents an error in a JSON-RPC response
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCP-specific structures (same as before)
type ClientCapabilities struct {
	Experimental   map[string]interface{} `json:"experimental,omitempty"`
	Sampling       *SamplingCapability    `json:"sampling,omitempty"`
	Authentication *Authentication        `json:"authentication,omitempty"`
}

type Authentication struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}

type SamplingCapability struct{}

type ServerCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Logging      *LoggingCapability     `json:"logging,omitempty"`
	Prompts      *PromptsCapability     `json:"prompts,omitempty"`
	Resources    *ResourcesCapability   `json:"resources,omitempty"`
	Tools        *ToolsCapability       `json:"tools,omitempty"`
}

type LoggingCapability struct{}
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      ClientInfo         `json:"clientInfo"`
}

type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

// ResponseTracker tracks pending requests and cancellations
type ResponseTracker struct {
	mu            sync.RWMutex
	responses     map[interface{}]chan JSONRPCMessage
	cancellations map[interface{}]context.CancelFunc
}

func NewResponseTracker() *ResponseTracker {
	return &ResponseTracker{
		responses:     make(map[interface{}]chan JSONRPCMessage),
		cancellations: make(map[interface{}]context.CancelFunc),
	}
}

func (rt *ResponseTracker) AddRequest(id interface{}, cancel context.CancelFunc) chan JSONRPCMessage {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	ch := make(chan JSONRPCMessage, 1)
	rt.responses[id] = ch
	if cancel != nil {
		rt.cancellations[id] = cancel
	}
	return ch
}

func (rt *ResponseTracker) HandleResponse(msg JSONRPCMessage) bool {
	if msg.ID == nil {
		return false // notification
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Convert msg.ID to string for comparison since JSON unmarshaling might change types
	var idStr string
	switch v := msg.ID.(type) {
	case int:
		idStr = strconv.Itoa(v)
	case float64:
		idStr = strconv.Itoa(int(v))
	case string:
		idStr = v
	default:
		idStr = fmt.Sprintf("%v", v)
	}

	// Check both the original ID and string representation
	for key, ch := range rt.responses {
		var keyStr string
		switch v := key.(type) {
		case int:
			keyStr = strconv.Itoa(v)
		case float64:
			keyStr = strconv.Itoa(int(v))
		case string:
			keyStr = v
		default:
			keyStr = fmt.Sprintf("%v", v)
		}

		if key == msg.ID || keyStr == idStr {
			ch <- msg
			close(ch)
			delete(rt.responses, key)
			delete(rt.cancellations, key)
			return true
		}
	}
	return false
}

func (rt *ResponseTracker) CancelRequest(id interface{}) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if cancel, exists := rt.cancellations[id]; exists {
		cancel()
		if ch, exists := rt.responses[id]; exists {
			close(ch)
			delete(rt.responses, id)
		}
		delete(rt.cancellations, id)
	}
}

type StdioMCPClient struct {
	cmd            *exec.Cmd
	stdin          io.WriteCloser
	stdout         io.ReadCloser
	stderr         io.ReadCloser
	tracker        *ResponseTracker
	serverCaps     ServerCapabilities
	nextID         int
	mu             sync.Mutex
	logLevel       string
	subscriptions  map[string]bool
	requireConsent bool
	reader         *bufio.Reader
	encoder        *json.Encoder
	decoder        *json.Decoder
	serverInfo     ServerInfo
	token          string
	cancel         context.CancelFunc
}

func NewStdioMCPClient(reader *bufio.Reader, requireConsent bool, token string) *StdioMCPClient {
	return &StdioMCPClient{
		tracker:        NewResponseTracker(),
		nextID:         1,
		logLevel:       "info",
		subscriptions:  make(map[string]bool),
		requireConsent: requireConsent,
		reader:         reader,
		token:          token,
	}
}

func (c *StdioMCPClient) getNextID() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextID
	c.nextID++
	return id
}

// getUserConsent prompts the user for consent before executing potentially dangerous operations
func (c *StdioMCPClient) getUserConsent(operation, details string) bool {
	if !c.requireConsent {
		return true
	}

	safePrint("\n🚨 CONSENT REQUIRED 🚨\n")
	safePrint("Operation: %s\n", operation)
	if details != "" {
		safePrint("Details: %s\n", details)
	}
	safePrint("Do you want to proceed? (y/N): ")

	response, _ := c.reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

func (c *StdioMCPClient) promptString(reader *bufio.Reader, prompt string) string {
	safePrint(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// ConnectToServer starts an MCP server process and connects to it via stdio
func (c *StdioMCPClient) ConnectToServer(serverCommand []string) error {
	if len(serverCommand) == 0 {
		return fmt.Errorf("server command required")
	}

	safePrint("Starting MCP server: %s\n", strings.Join(serverCommand, " "))
	c.cmd = exec.Command(serverCommand[0], serverCommand[1:]...)

	var err error
	c.stdin, err = c.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	c.stdout, err = c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	c.stderr, err = c.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	err = c.cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	c.encoder = json.NewEncoder(c.stdin)
	c.decoder = json.NewDecoder(c.stdout)

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.startMessageHandler(ctx)

	safePrint("✅ MCP server started (PID: %d)\n", c.cmd.Process.Pid)
	return nil
}

var terminalMu sync.Mutex

func safePrint(format string, args ...interface{}) {
	terminalMu.Lock()
	defer terminalMu.Unlock()
	fmt.Printf(format, args...)
}

//	func (c *StdioMCPClient) prettyPrint(data interface{}) {
//		jsonData, err := json.MarshalIndent(data, "", "  ")
//		if err != nil {
//			fmt.Printf("%+v\n", data)
//		} else {
//			fmt.Println(string(jsonData))
//		}
//	}
func (c *StdioMCPClient) startMessageHandler(ctx context.Context) {
	go func() {
		scanner := bufio.NewScanner(c.stderr)
		for scanner.Scan() && ctx.Err() == nil {
			line := scanner.Text()
			if line != "" {
				safePrint("🔍 Server stderr: %s\n", line)
			}
		}
		safePrint("DEBUG: stderr scanner exited\n")
	}()

	go func() {
		for ctx.Err() == nil {
			var message JSONRPCMessage
			err := c.decoder.Decode(&message)
			if err != nil {
				if err == io.EOF {
					safePrint("📡 Server connection closed\n")
					return
				}
				safePrint("Failed to decode message: %v\n", err)
				continue
			}
			if !c.tracker.HandleResponse(message) {
				c.handleNotification(message)
			}
		}
		safePrint("DEBUG: stdout handler exited\n")
	}()
}

func (c *StdioMCPClient) initializeMCP() error {
	initParams := InitializeParams{
		ProtocolVersion: MCP_PROTOCOL_VERSION,
		Capabilities: ClientCapabilities{
			Sampling: &SamplingCapability{},
		},
		ClientInfo: ClientInfo{
			Name:    "go-stdio-mcp-client",
			Version: "1.0.0",
		},
	}

	if c.token != "" {
		initParams.Capabilities.Authentication = &Authentication{
			Type:  "Bearer", // Hardcoded for now, can be made configurable
			Token: c.token,
		}
	}

	initMessage := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      c.getNextID(),
		Method:  "initialize",
		Params:  initParams,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	responseCh := c.tracker.AddRequest(initMessage.ID, cancel)

	err := c.encoder.Encode(initMessage)
	if err != nil {
		return fmt.Errorf("failed to send initialize: %w", err)
	}

	// Wait for initialize response
	select {
	case response := <-responseCh:
		if response.Error != nil {
			return fmt.Errorf("initialize error: %s", response.Error.Message)
		}

		// Parse server capabilities
		if response.Result != nil {
			resultBytes, _ := json.Marshal(response.Result)
			var initResult InitializeResult
			if err := json.Unmarshal(resultBytes, &initResult); err == nil {
				c.serverCaps = initResult.Capabilities
				c.serverInfo = initResult.ServerInfo
				fmt.Printf("Server: %s v%s\n", c.serverInfo.Name, c.serverInfo.Version)
				fmt.Printf("Protocol: %s\n", initResult.ProtocolVersion)
				fmt.Printf("Capabilities: Tools=%v, Resources=%v, Prompts=%v, Logging=%v\n",
					c.serverCaps.Tools != nil,
					c.serverCaps.Resources != nil,
					c.serverCaps.Prompts != nil,
					c.serverCaps.Logging != nil)
			}
		}
	case <-ctx.Done():
		return fmt.Errorf("initialize timeout")
	}

	// Send initialized notification
	initializedMessage := JSONRPCMessage{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}

	return c.encoder.Encode(initializedMessage)
}

func (c *StdioMCPClient) handleNotification(msg JSONRPCMessage) {
	// Buffer notifications to avoid flooding
	type notification struct {
		Method string
		Params interface{}
	}
	notificationCh := make(chan notification, 100)
	go func() {
		for n := range notificationCh {
			switch n.Method {
			case "notifications/progress":
				if params, ok := n.Params.(map[string]interface{}); ok {
					token := params["progressToken"]
					progress := params["progress"]
					total := params["total"]
					safePrint("\n📊 Progress %v: %v", token, progress)
					if total != nil {
						safePrint("/%v", total)
					}
					safePrint("\n")
				}
			// ... other cases
			default:
				safePrint("\n🔔 Unknown notification: %s\n", n.Method)
				if n.Params != nil {
					c.prettyPrint(n.Params)
				}
			}
			safePrint("Enter command: ")
		}
	}()

	// Send notification to channel
	notificationCh <- notification{Method: msg.Method, Params: msg.Params}
}

func (c *StdioMCPClient) prettyPrint(data interface{}) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("%+v\n", data)
	} else {
		fmt.Println(string(jsonData))
	}
}
func (c *StdioMCPClient) sendRequest(method string, params interface{}) error {
	message := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      c.getNextID(),
		Method:  method,
		Params:  params,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	responseCh := c.tracker.AddRequest(message.ID, cancel)

	err := c.encoder.Encode(message)
	if err != nil {
		return fmt.Errorf("write error: %w", err)
	}

	select {
	case response := <-responseCh:
		c.handleResponse(response)
	case <-ctx.Done():
		fmt.Println("⏰ Request timed out")
	}

	return nil
}

func (c *StdioMCPClient) handleResponse(response JSONRPCMessage) {
	if response.Error != nil {
		fmt.Printf("❌ Error %d: %s\n", response.Error.Code, response.Error.Message)
		if response.Error.Data != nil {
			fmt.Print("Error details: ")
			c.prettyPrint(response.Error.Data)
		}
	} else {
		fmt.Println("✅ Success:")
		c.prettyPrint(response.Result)
	}
}

// All the command handling methods (same as WebSocket version)
func (c *StdioMCPClient) handleCommand(input string, reader *bufio.Reader) error {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil
	}

	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "tools/list", "tl":
		return c.sendRequest("tools/list", nil)

	case "tools/call", "tc":
		return c.handleToolCall(args, reader)

	case "resources/list", "rl":
		return c.sendRequest("resources/list", nil)

	case "resources/read", "rr":
		return c.handleResourceRead(args, reader)

	case "resources/subscribe", "rs":
		return c.handleResourceSubscribe(args, reader)

	case "resources/unsubscribe", "ru":
		return c.handleResourceUnsubscribe(args, reader)

	case "prompts/list", "pl":
		return c.sendRequest("prompts/list", nil)

	case "prompts/get", "pg":
		return c.handlePromptGet(args, reader)

	case "logging/setLevel", "log":
		return c.handleSetLogLevel(args, reader)

	case "cancel":
		return c.handleCancel(args, reader)

	case "ping":
		return c.sendRequest("ping", nil)

	default:
		fmt.Printf("❌ Unknown command: %s (type 'help' for available commands)\n", cmd)
		return nil
	}
}

func (c *StdioMCPClient) handleToolCall(args []string, reader *bufio.Reader) error {
	var toolName string
	if len(args) > 0 {
		toolName = args[0]
	} else {
		toolName = c.promptString(reader, "Enter tool name: ")
	}

	if toolName == "" {
		return fmt.Errorf("tool name required")
	}

	fmt.Print("Enter arguments (as JSON, or press Enter for empty): ")
	argsInput, _ := reader.ReadString('\n')
	argsInput = strings.TrimSpace(argsInput)

	var argsMap map[string]interface{}
	if argsInput != "" {
		err := json.Unmarshal([]byte(argsInput), &argsMap)
		if err != nil {
			return fmt.Errorf("invalid JSON arguments: %w", err)
		}
	}

	// Request user consent for tool execution
	details := fmt.Sprintf("Tool: %s", toolName)
	if len(argsMap) > 0 {
		if argsJSON, err := json.Marshal(argsMap); err == nil {
			details += fmt.Sprintf("\nArguments: %s", string(argsJSON))
		}
	}

	if !c.getUserConsent("Execute Tool", details) {
		fmt.Println("❌ Tool execution cancelled by user")
		return nil
	}

	params := map[string]interface{}{
		"name":      toolName,
		"arguments": argsMap,
	}

	return c.sendRequest("tools/call", params)
}

func (c *StdioMCPClient) handleResourceRead(args []string, reader *bufio.Reader) error {
	var uri string
	if len(args) > 0 {
		uri = args[0]
	} else {
		uri = c.promptString(reader, "Enter resource URI: ")
	}

	if uri == "" {
		return fmt.Errorf("resource URI required")
	}

	if !c.getUserConsent("Read Resource", fmt.Sprintf("URI: %s", uri)) {
		fmt.Println("❌ Resource read cancelled by user")
		return nil
	}

	params := map[string]interface{}{
		"uri": uri,
	}

	return c.sendRequest("resources/read", params)
}

func (c *StdioMCPClient) handleResourceSubscribe(args []string, reader *bufio.Reader) error {
	var uri string
	if len(args) > 0 {
		uri = args[0]
	} else {
		uri = c.promptString(reader, "Enter resource URI to subscribe: ")
	}

	if uri == "" {
		return fmt.Errorf("resource URI required")
	}

	if !c.getUserConsent("Subscribe to Resource", fmt.Sprintf("URI: %s", uri)) {
		fmt.Println("❌ Resource subscription cancelled by user")
		return nil
	}

	c.subscriptions[uri] = true
	params := map[string]interface{}{
		"uri": uri,
	}

	return c.sendRequest("resources/subscribe", params)
}

func (c *StdioMCPClient) handleResourceUnsubscribe(args []string, reader *bufio.Reader) error {
	var uri string
	if len(args) > 0 {
		uri = args[0]
	} else {
		uri = c.promptString(reader, "Enter resource URI to unsubscribe: ")
	}

	if uri == "" {
		return fmt.Errorf("resource URI required")
	}

	delete(c.subscriptions, uri)
	params := map[string]interface{}{
		"uri": uri,
	}

	return c.sendRequest("resources/unsubscribe", params)
}

func (c *StdioMCPClient) handlePromptGet(args []string, reader *bufio.Reader) error {
	var promptName string
	if len(args) > 0 {
		promptName = args[0]
	} else {
		promptName = c.promptString(reader, "Enter prompt name: ")
	}

	if promptName == "" {
		return fmt.Errorf("prompt name required")
	}

	fmt.Print("Enter arguments (as JSON, or press Enter for empty): ")
	argsInput, _ := reader.ReadString('\n')
	argsInput = strings.TrimSpace(argsInput)

	var argsMap map[string]interface{}
	if argsInput != "" {
		err := json.Unmarshal([]byte(argsInput), &argsMap)
		if err != nil {
			return fmt.Errorf("invalid JSON arguments: %w", err)
		}
	}

	params := map[string]interface{}{
		"name":      promptName,
		"arguments": argsMap,
	}

	return c.sendRequest("prompts/get", params)
}

func (c *StdioMCPClient) handleSetLogLevel(args []string, reader *bufio.Reader) error {
	var level string
	if len(args) > 0 {
		level = args[0]
	} else {
		level = c.promptString(reader, "Enter log level (debug, info, notice, warning, error, critical, alert, emergency): ")
	}

	if level == "" {
		return fmt.Errorf("log level required")
	}

	c.logLevel = level
	params := map[string]interface{}{
		"level": level,
	}

	return c.sendRequest("logging/setLevel", params)
}

func (c *StdioMCPClient) handleCancel(args []string, reader *bufio.Reader) error {
	var idStr string
	if len(args) > 0 {
		idStr = args[0]
	} else {
		idStr = c.promptString(reader, "Enter request ID to cancel: ")
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fmt.Errorf("invalid request ID: %w", err)
	}

	c.tracker.CancelRequest(id)

	// Send cancellation notification
	cancelMessage := JSONRPCMessage{
		JSONRPC: "2.0",
		Method:  "notifications/cancelled",
		Params: map[string]interface{}{
			"requestId": id,
		},
	}

	return c.encoder.Encode(cancelMessage)
}

// func (c *StdioMCPClient) promptString(reader *bufio.Reader, prompt string) string {
// 	fmt.Print(prompt)
// 	input, _ := reader.ReadString('\n')
// 	return strings.TrimSpace(input)
// }

func (c *StdioMCPClient) Close() error {
	if c.cancel != nil {
		c.cancel() // Cancel the context to stop message handlers
	}
	if c.stdin != nil {
		c.stdin.Close()
	}
	if c.stdout != nil {
		c.stdout.Close()
	}
	if c.stderr != nil {
		c.stderr.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		c.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() {
			done <- c.cmd.Wait()
		}()
		select {
		case <-done:
			safePrint("📡 Server shut down gracefully\n")
		case <-time.After(5 * time.Second):
			safePrint("🔪 Force killing server\n")
			c.cmd.Process.Kill()
		}
	}
	return nil
}

// ClientManager manages multiple MCP server connections
type ClientManager struct {
	mu             sync.RWMutex
	clients        map[string]*StdioMCPClient
	activeClient   *StdioMCPClient
	activeAlias    string
	reader         *bufio.Reader
	requireConsent bool
	token          string // New field for global token override
}

func NewClientManager(requireConsent bool, token string) *ClientManager {
	return &ClientManager{
		clients:        make(map[string]*StdioMCPClient),
		reader:         bufio.NewReader(os.Stdin),
		requireConsent: requireConsent,
		token:          token,
	}
}

// loadServersFromConfig connects to all servers defined in the config
func (m *ClientManager) loadServersFromConfig() error {
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if len(config.MCPServers) == 0 {
		fmt.Println("ℹ️ No servers defined in config file")
		return nil
	}

	fmt.Println("📋 Loading servers from configuration...")
	for alias, serverConfig := range config.MCPServers {
		serverCmd := append([]string{serverConfig.Command}, serverConfig.Args...)
		token := serverConfig.Token
		if token == "" {
			token = extractTokenFromArgs(serverConfig.Args)
		}
		if m.token != "" {
			token = m.token // Override with command-line token
		}

		fmt.Printf("Connecting to '%s'...\n", alias)
		if err := m.Connect(alias, serverCmd, token); err != nil {
			fmt.Printf("❌ Failed to connect to '%s': %v\n", alias, err)
			continue
		}
	}
	return nil
}

func (m *ClientManager) Connect(alias string, serverCommand []string, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.clients[alias]; exists {
		return fmt.Errorf("client with alias '%s' already exists", alias)
	}

	if len(serverCommand) == 0 {
		return fmt.Errorf("server command required")
	}

	client := NewStdioMCPClient(m.reader, m.requireConsent, token)

	err := client.ConnectToServer(serverCommand)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	// startMessageHandler is now called inside ConnectToServer with context
	safePrint("Initializing MCP session for '%s'...\n", alias)
	if err := client.initializeMCP(); err != nil {
		client.Close()
		return fmt.Errorf("failed to initialize MCP for '%s': %w", alias, err)
	}
	safePrint("✅ MCP session for '%s' initialized successfully!\n", alias)

	m.clients[alias] = client
	if m.activeClient == nil {
		m.activeClient = client
		m.activeAlias = alias
		safePrint("'%s' is now the active server.\n", alias)
	}

	return nil
}

func (m *ClientManager) Disconnect(alias string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	client, exists := m.clients[alias]
	if !exists {
		return fmt.Errorf("no client with alias '%s' found", alias)
	}

	fmt.Printf("Disconnecting from '%s'...\n", alias)
	client.Close()
	delete(m.clients, alias)

	if m.activeAlias == alias {
		m.activeClient = nil
		m.activeAlias = ""
		fmt.Println("Active server disconnected.")
		// Switch to another server if available
		if len(m.clients) > 0 {
			for newAlias, newClient := range m.clients {
				m.activeAlias = newAlias
				m.activeClient = newClient
				fmt.Printf("Switched active server to '%s'.\n", newAlias)
				break
			}
		}
	}

	return nil
}

func (m *ClientManager) Switch(alias string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	client, exists := m.clients[alias]
	if !exists {
		return fmt.Errorf("no client with alias '%s' found", alias)
	}

	m.activeClient = client
	m.activeAlias = alias
	fmt.Printf("Switched to server '%s'.\n", alias)
	return nil
}

func (m *ClientManager) ListServers() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.clients) == 0 {
		fmt.Println("No active server connections.")
		return
	}

	fmt.Println("Active server connections:")
	for alias, client := range m.clients {
		activeMarker := " "
		if alias == m.activeAlias {
			activeMarker = "*"
		}
		serverName := "unknown"
		serverVersion := "unknown"
		if client.serverInfo.Name != "" {
			serverName = client.serverInfo.Name
			serverVersion = client.serverInfo.Version
		}
		fmt.Printf(" %s %s (%s v%s)\n", activeMarker, alias, serverName, serverVersion)
	}
}

func (m *ClientManager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for alias, client := range m.clients {
		fmt.Printf("Closing connection '%s'...\n", alias)
		client.Close()
	}
	m.clients = make(map[string]*StdioMCPClient)
	m.activeClient = nil
	m.activeAlias = ""
}

func (m *ClientManager) toggleConsent() {
	m.mu.Lock()
	m.requireConsent = !m.requireConsent
	// Propagate change to existing clients
	for _, client := range m.clients {
		client.requireConsent = m.requireConsent
	}
	m.mu.Unlock()

	if m.requireConsent {
		fmt.Println("✅ User consent is now ENABLED for all sessions.")
	} else {
		fmt.Println("⚠️ User consent is now DISABLED for all sessions.")
	}
}

func (m *ClientManager) printHelp() {
	consentStatus := "ENABLED"
	if !m.requireConsent {
		consentStatus = "DISABLED"
	}

	fmt.Printf(`
📋 MCP Client Manager Commands:
  connect <alias> <command...> - Connect to a new MCP server
    Example: connect gh npx @modelcontextprotocol/server-github
    Example2: connect hf npx mcp-remote https://huggingface.co/mcp --token <YOUR HF TOKEN>
  disconnect <alias>           - Disconnect from a server
  switch <alias>               - Switch the active server
  servers                      - List all active server connections
  consent                      - Toggle user consent for all sessions (current: %s)
  help                         - Show this help message
  exit/quit                    - Disconnect all servers and exit

Once connected, you can use server-specific commands on the active server:
  tools/list        (tl) - List available tools
  tools/call        (tc) - Call a specific tool
  resources/list    (rl) - List available resources
  resources/read    (rr) - Read a specific resource
    resources/subscribe (rs) - Subscribe to resource updates
    resources/unsubscribe (ru) - Unsubscribe from resource
    prompts/list      (pl) - List available prompts
    prompts/get       (pg) - Get a specific prompt

  MCP Utilities:
    logging/setLevel  (log) - Set logging level
    cancel <id>       - Cancel a request by ID
    ping              - Ping the server

  Client Commands:
    help              - Show this help message
    consent           - Toggle user consent (current: %s)
    exit/quit         - Exit the client

💡 Tips:
  - You can use short aliases (tl, tc, rl, rr, rs, ru, pl, pg, log)
  - Commands can take arguments: tc mytool, rr myuri
  - JSON arguments can be left empty (just press Enter)
  - Use Ctrl+C to interrupt at any time
  - Server notifications will appear automatically

🔒 Security Features:
  - User consent prompts for dangerous operations
  - Use --no-consent flag to disable consent prompts

📡 Stdio Transport:
  - Communicates with MCP servers via stdin/stdout
  - Compatible with most existing MCP servers
  - Automatically manages server process lifecycle

`, consentStatus)
}

func (m *ClientManager) run() {
	for {
		prompt := "> "
		if m.activeAlias != "" {
			prompt = fmt.Sprintf("[%s]> ", m.activeAlias)
		}
		safePrint(prompt)

		// Use the manager's shared reader for all input
		input, err := m.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println() // Add a newline for a clean exit on Ctrl+D
				return
			}
			safePrint("Error reading input: %v\n", err)
			continue
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "exit", "quit":
			return
		case "help":
			m.printHelp()
		case "consent":
			m.toggleConsent()
		case "connect":
			if len(args) < 2 {
				safePrint("Usage: connect <alias> <command...>\n")
				continue
			}
			alias := args[0]
			serverCmd := args[1:]
			if err := m.Connect(alias, serverCmd, m.token); err != nil {
				safePrint("❌ Error connecting: %v\n", err)
			}
		case "disconnect":
			if len(args) < 1 {
				safePrint("Usage: disconnect <alias>\n")
				continue
			}
			if err := m.Disconnect(args[0]); err != nil {
				safePrint("❌ Error disconnecting: %v\n", err)
			}
		case "switch":
			if len(args) < 1 {
				safePrint("Usage: switch <alias>\n")
				continue
			}
			if err := m.Switch(args[0]); err != nil {
				safePrint("❌ Error switching: %v\n", err)
			}
		case "servers":
			m.ListServers()
		default:
			if m.activeClient != nil {
				// Pass the manager's shared reader to the command handler
				if err := m.activeClient.handleCommand(input, m.reader); err != nil {
					safePrint("❌ Error: %v\n", err)
				}
			} else {
				safePrint("No active server. Use 'connect' to start a new connection or 'switch' to an existing one.\n")
			}
		}
	}
}



func main() {
	// Default settings
	requireConsent := true
	token := ""
	serverCommand := []string{}

	// Parse command-line arguments
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--no-consent" {
			requireConsent = false
		} else if os.Args[i] == "--token" && i+1 < len(os.Args) {
			token = os.Args[i+1]
			i++
		} else {
			serverCommand = append(serverCommand, os.Args[i])
		}
	}

	manager := NewClientManager(requireConsent, token)
	if !manager.requireConsent {
		fmt.Println("⚠️ User consent disabled by flag - commands will execute automatically")
	}

	// Set up signal handling
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interrupt
		fmt.Println("\n📡 Shutting down all connections...")
		manager.CloseAll()
		os.Exit(0)
	}()
	defer manager.CloseAll()

	fmt.Println("Go MCP Client - Multi-Server Edition")
	fmt.Println("Type 'help' for a list of commands.")

	// Load servers from config file
	if err := manager.loadServersFromConfig(); err != nil {
		log.Printf("❌ Failed to load servers from config: %v", err)
	}

	// Connect to server from command-line arguments (if provided)
	if len(serverCommand) > 0 {
		alias := "default"
		if len(serverCommand) > 1 && strings.Contains(serverCommand[1], "server-") {
			parts := strings.Split(serverCommand[1], "server-")
			if len(parts) > 1 {
				alias = parts[1]
			}
		} else if len(serverCommand) > 0 {
			parts := strings.Split(serverCommand[0], string(os.PathSeparator))
			alias = parts[len(parts)-1]
		}

		fmt.Printf("\nAttempting to connect to initial server with alias '%s'...\n", alias)
		if err := manager.Connect(alias, serverCommand, token); err != nil {
			log.Printf("❌ Failed to connect to initial server: %v", err)
		}
	}

	manager.run()
	fmt.Println("👋 Goodbye!")
}

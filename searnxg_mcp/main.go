package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	serverName    = "mcp-searxng-go"
	serverVersion = "0.1.0"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Create a new MCP Server
	server := mcp.NewServer(serverName, serverVersion, &mcp.ServerOptions{
		Instructions: "This server provides web search via SearXNG and URL content reading.",
	})

	// 2. Create and add the searxng_web_search tool
	searxngWebSearchTool := mcp.NewServerTool(
		"searxng_web_search",
		"Execute web searches with pagination, time filtering, language selection, and safe search.",
		searxngWebSearchHandler,
	)
	server.AddTools(searxngWebSearchTool)

	// 3. Create and add the web_url_read tool
	// webURLReadTool := mcp.NewServerTool(
	// 	"web_url_read",
	// 	"Read and convert the content from a URL to markdown.",
	// 	webURLReadHandler,
	// )
	//server.AddTools(webURLReadTool)

	log.Printf("%s v%s starting...", serverName, serverVersion)

	// Check for SearXNG URL and Auth early
	searxngURL := getSearxngURL() // from searxng_handlers.go
	log.Printf("Using SearXNG instance URL: %s", searxngURL)
	if os.Getenv("AUTH_USERNAME") != "" && os.Getenv("AUTH_PASSWORD") != "" {
		log.Println("SearXNG basic authentication (username/password) is configured.")
	} else if os.Getenv("AUTH_USERNAME") != "" || os.Getenv("AUTH_PASSWORD") != "" {
		log.Println("Warning: Partial SearXNG authentication found. Both AUTH_USERNAME and AUTH_PASSWORD must be set.")
	}

	// 4. Create StdioTransport
	transport := mcp.NewStdioTransport()

	// 5. Run the server
	log.Println("Attempting to run server with StdioTransport...")
	if err := server.Run(ctx, transport); err != nil {
		// Handle specific errors that indicate normal shutdown
		if err == context.Canceled || strings.Contains(err.Error(), "connection closed") || strings.Contains(err.Error(), "io: read/write on closed pipe") {
			log.Println("Server shutdown initiated:", err)
		} else {
			log.Fatalf("MCP Server error: %v", err)
		}
	}

	log.Println("Server has shut down.")
}

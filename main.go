package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Operation defines a single filesystem operation.
type Operation struct {
	Type    string `json:"type"`
	Path    string `json:"path"`
	Content string `json:"content,omitempty"` // Used for create_file
}

// ApplyFilesystemManifestArgs defines the arguments for the apply_filesystem_manifest tool.
type ApplyFilesystemManifestArgs struct {
	Operations []Operation `json:"operations"`
}

// applyFilesystemManifest implements the logic for the apply_filesystem_manifest tool.
func applyFilesystemManifest(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[ApplyFilesystemManifestArgs]) (*mcp.CallToolResultFor[any], error) {
	log.Printf("Received apply_filesystem_manifest request with %d operations", len(params.Arguments.Operations))
	for _, op := range params.Arguments.Operations {
		log.Printf("Processing operation: Type=%s, Path=%s", op.Type, op.Path)
		switch op.Type {
		case "create_directory":
			err := os.MkdirAll(op.Path, 0755)
			if err != nil {
				log.Printf("Error creating directory %s: %v", op.Path, err)
				return &mcp.CallToolResultFor[any]{
					IsError: true,
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error creating directory %s: %v", op.Path, err)}},
				}, nil
			}
			log.Printf("Successfully created directory: %s", op.Path)
		case "create_file":
			err := os.WriteFile(op.Path, []byte(op.Content), 0644)
			if err != nil {
				log.Printf("Error creating file %s: %v", op.Path, err)
				return &mcp.CallToolResultFor[any]{
					IsError: true,
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error creating file %s: %v", op.Path, err)}},
				}, nil
			}
			log.Printf("Successfully created file: %s", op.Path)
		default:
			errMsg := fmt.Sprintf("Unsupported operation type: %s", op.Type)
			log.Printf(errMsg)
			return &mcp.CallToolResultFor[any]{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: errMsg}},
			}, nil
		}
	}

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: "Filesystem manifest applied successfully."}},
	}, nil
}

func main() {
	// Create a server with the apply_filesystem_manifest tool.
	server := mcp.NewServer("filesystem-mcp", "v1.0.0", nil)
	server.AddTools(
		mcp.NewServerTool(
			"apply_filesystem_manifest",
			"Applies a manifest of filesystem operations (create_directory, create_file).",
			applyFilesystemManifest,
			mcp.Input( // ToolOption: defines the input schema for the tool. It's an object.
				// SchemaOptions for the implicit root object:
				mcp.Property("operations", // This is a SchemaOption, defines a property of the root object.
					// ...and these are SchemaOptions for the "operations" property itself:
					mcp.Description("A list of filesystem operations to perform."),
					mcp.Required(true), // Mark the 'operations' property as required
					mcp.Schema(&jsonschema.Schema{ // This defines the actual type and constraints of "operations"
						Type: "array",
						// Description for the array type itself can be part of jsonschema.Schema
						// but mcp.Description above is likely for the property's description.
						Items: &jsonschema.Schema{
							Type: "object",
							Properties: map[string]*jsonschema.Schema{
								"type": {
									Type:        "string",
									Description: "The type of operation.",
									Enum:        []any{"create_directory", "create_file"},
								},
								"path": {
									Type:        "string",
									Description: "The path for the operation.",
								},
								"content": {
									Type:        "string",
									Description: "The content for the file (optional, only for create_file).",
								},
							},
							Required: []string{"type", "path"}, // Fields required within each Operation object
						},
					}),
				), // End of mcp.Property("operations")
			), // End of mcp.Input()
		), // Close NewServerTool
	)

	log.Println("Filesystem MCP server starting...")
	// Run the server over stdin/stdout, until the client disconnects.
	if err := server.Run(context.Background(), mcp.NewStdioTransport()); err != nil {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Filesystem MCP server stopped.")
}

package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// stringSlice is a custom type for flag package to handle multiple string inputs for a flag
type stringSlice []string

func (i *stringSlice) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *stringSlice) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var allowedWriteDirs stringSlice
var allowedWriteDirsAbs []string // To store absolute paths for comparison

func init() {
	flag.Var(&allowedWriteDirs, "allowed-dirs", "Directory where write operations are allowed. Can be specified multiple times.")
	flag.Parse()

	if len(allowedWriteDirs) == 0 {
		// If no dirs are specified, default to allowing writes in the current working directory.
		// This is a design decision. Alternatively, could deny all writes by default.
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current working directory: %v", err)
		}
		absCwd, err := filepath.Abs(cwd)
		if err != nil {
			log.Fatalf("Failed to get absolute path for current working directory: %v", err)
		}
		allowedWriteDirsAbs = append(allowedWriteDirsAbs, absCwd)
		log.Printf("No --allowed-dirs specified, defaulting to current working directory: %s", absCwd)
	} else {
		for _, dir := range allowedWriteDirs {
			absDir, err := filepath.Abs(dir)
			if err != nil {
				log.Fatalf("Failed to get absolute path for allowed directory %s: %v", dir, err)
			}
			// Ensure the directory exists, or at least can be stated.
			// This is a basic check; more robust validation could be added.
			_, statErr := os.Stat(absDir)
			if os.IsNotExist(statErr) {
				// Option: Create the directory if it doesn't exist?
				// For now, let's require it to exist or be creatable by the user beforehand.
				log.Printf("Warning: Allowed directory %s (resolved to %s) does not exist. Write operations to it might fail if it's not created.", dir, absDir)
			} else if statErr != nil {
				log.Fatalf("Error stating allowed directory %s (resolved to %s): %v", dir, absDir, statErr)
			}
			allowedWriteDirsAbs = append(allowedWriteDirsAbs, absDir)
		}
	}
	log.Printf("Allowed write directories (absolute): %v", allowedWriteDirsAbs)
}

// isPathAllowed checks if the targetPath is within the allowedWriteDirsAbs for write operations.
// operationType is for logging/error messages.
func isPathAllowed(targetPath string, operationType string) error {
	if len(allowedWriteDirsAbs) == 0 {
		// This case should ideally be handled by init defaulting to CWD or explicit configuration.
		// If it somehow reaches here, it means no restrictions are set, which might be a security risk.
		// For safety, let's assume if allowedWriteDirsAbs is empty, no writes are allowed unless it defaulted to CWD.
		// The init() function ensures allowedWriteDirsAbs is never empty if the program runs.
		log.Printf("Security check: allowedWriteDirsAbs is empty. This state should not be reached if init() ran correctly.")
		return fmt.Errorf("operation %s on path %s is denied: no allowed write directories configured (this is a server misconfiguration)", operationType, targetPath)
	}

	absTargetPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("could not get absolute path for %s: %w", targetPath, err)
	}

	for _, allowedDir := range allowedWriteDirsAbs {
		// Check if absTargetPath is within or is the same as allowedDir
		if strings.HasPrefix(absTargetPath, allowedDir+string(os.PathSeparator)) || absTargetPath == allowedDir {
			log.Printf("Path %s is allowed for %s under %s", absTargetPath, operationType, allowedDir)
			return nil // Path is allowed
		}
	}

	log.Printf("Path %s is NOT allowed for %s. Allowed directories: %v", absTargetPath, operationType, allowedWriteDirsAbs)
	return fmt.Errorf("operation %s on path %s is denied: path is not within allowed write directories %v", operationType, targetPath, allowedWriteDirsAbs)
}


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

// Structs for new file system tools

// ListDirectoryArgs defines arguments for list_directory tool
type ListDirectoryArgs struct {
	Path           string `json:"path"`
	Recursive      bool   `json:"recursive,omitempty"`
	MaxDepth       int    `json:"max_depth,omitempty"`
	IncludeHidden  bool   `json:"include_hidden,omitempty"`
}

// FileSystemItem represents a file or directory in a listing
type FileSystemItem struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"` // "file" or "directory"
	Size         int64     `json:"size,omitempty"` // For files
	LastModified time.Time `json:"last_modified"`
	Path         string    `json:"path"`
}

// ListDirectoryResult defines the result for list_directory tool
type ListDirectoryResult struct {
	Items []FileSystemItem `json:"items"`
}

// MoveItemArgs defines arguments for move_item tool
type MoveItemArgs struct {
	SourcePath      string `json:"source_path"`
	DestinationPath string `json:"destination_path"`
}

// CopyItemArgs defines arguments for copy_item tool
type CopyItemArgs struct {
	SourcePath      string `json:"source_path"`
	DestinationPath string `json:"destination_path"`
	Overwrite       bool   `json:"overwrite,omitempty"`
}

// DeleteItemArgs defines arguments for delete_item tool
type DeleteItemArgs struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"`
}

// ReadFileArgs defines arguments for read_file tool
type ReadFileArgs struct {
	Path     string `json:"path"`
	Encoding string `json:"encoding,omitempty"` // "utf-8", "base64"
}

// ReadFileResult defines the result for read_file tool
type ReadFileResult struct {
	Content  string `json:"content"`
	MimeType string `json:"mime_type"`
}

// WriteFileArgs defines arguments for write_file tool
type WriteFileArgs struct {
	Path     string `json:"path"`
	Content  string `json:"content"`
	Append   bool   `json:"append,omitempty"`
	Encoding string `json:"encoding,omitempty"` // For content interpretation if needed
}

// GetItemPropertiesArgs defines arguments for get_item_properties tool
type GetItemPropertiesArgs struct {
	Path string `json:"path"`
}

// ItemProperties defines the detailed properties of a file or directory
type ItemProperties struct {
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Type         string    `json:"type"` // "file" or "directory"
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
	CreatedAt    time.Time `json:"created_at"`
	Permissions  string    `json:"permissions"` // e.g., "rwxr-xr-x"
	IsReadOnly   bool      `json:"is_readonly"`
}

// ItemExistsArgs defines arguments for item_exists tool
type ItemExistsArgs struct {
	Path string `json:"path"`
}

// ItemExistsResult defines the result for item_exists tool
type ItemExistsResult struct {
	Exists bool   `json:"exists"`
	Type   string `json:"type"` // "file", "directory", or "not_found"
}

// CreateArchiveArgs defines arguments for create_archive tool
type CreateArchiveArgs struct {
	SourcePaths  []string `json:"source_paths"`
	ArchivePath string   `json:"archive_path"`
	Format       string   `json:"format"` // "zip", "tar.gz"
}

// CreateArchiveResult defines the result for create_archive tool
type CreateArchiveResult struct {
	PathToArchive string `json:"path_to_archive"`
}

// ExtractArchiveArgs defines arguments for extract_archive tool
type ExtractArchiveArgs struct {
	ArchivePath     string `json:"archive_path"`
	DestinationPath string `json:"destination_path"`
	Format          string `json:"format,omitempty"` // Optional, auto-detect if possible
}

// GenericSuccessFailureResult can be used for tools that only return a success/failure message.
type GenericSuccessFailureResult struct {
	Message string `json:"message"`
}

// listDirectory implements the logic for the list_directory tool.
func listDirectory(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[ListDirectoryArgs]) (*mcp.CallToolResultFor[ListDirectoryResult], error) {
	log.Printf("Received list_directory request for path %s", params.Arguments.Path)
	var items []FileSystemItem
	err := listDirectoryRecursive(params.Arguments.Path, params.Arguments.Path, &items, params.Arguments.Recursive, params.Arguments.MaxDepth, params.Arguments.IncludeHidden, 0)
	if err != nil {
		log.Printf("Error listing directory %s: %v", params.Arguments.Path, err)
		return &mcp.CallToolResultFor[ListDirectoryResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error listing directory %s: %v", params.Arguments.Path, err)}},
		}, nil
	}

	// Prepare a simple text summary for the Content field
	summary := fmt.Sprintf("Found %d items in %s.", len(items), params.Arguments.Path)
	if len(items) > 10 {
		summary = fmt.Sprintf("Found %d items in %s. Showing first 10 here in text, full list in structured content.", len(items), params.Arguments.Path)
	}
	var textItems []string
	for i, item := range items {
		if i < 10 { // Limit text representation
			textItems = append(textItems, fmt.Sprintf("- %s (%s, %d bytes, mod: %s, path: %s)", item.Name, item.Type, item.Size, item.LastModified.Format(time.RFC3339), item.Path))
		}
	}
	textContent := summary + "\n" + strings.Join(textItems, "\n")


	return &mcp.CallToolResultFor[ListDirectoryResult]{
		StructuredContent: &ListDirectoryResult{Items: items},
		Content:           []mcp.Content{&mcp.TextContent{Text: textContent}},
	}, nil
}

// writeFile implements the logic for the write_file tool.
func writeFile(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[WriteFileArgs]) (*mcp.CallToolResultFor[GenericSuccessFailureResult], error) {
	log.Printf("Received write_file request for path %s, append: %t, encoding: %s", params.Arguments.Path, params.Arguments.Append, params.Arguments.Encoding)

	opType := "write_file"
	if err := isPathAllowed(params.Arguments.Path, opType); err != nil {
		log.Printf("Access denied for %s on path %s: %v", opType, params.Arguments.Path, err)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		}, nil
	}

	var dataToWrite []byte
	var err error

	inputContent := params.Arguments.Content
	actualEncoding := params.Arguments.Encoding
	if actualEncoding == "" {
		actualEncoding = "utf-8" // Assume utf-8 if not specified for content
	}

	switch actualEncoding {
	case "base64":
		dataToWrite, err = base64.StdEncoding.DecodeString(inputContent)
		if err != nil {
			log.Printf("Error decoding base64 content for file %s: %v", params.Arguments.Path, err)
			return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error decoding base64 content: %v", err)}},
			}, nil
		}
	case "utf-8":
		dataToWrite = []byte(inputContent)
	default:
		errMsg := fmt.Sprintf("unsupported encoding for write: %s. Supported encodings are 'utf-8' and 'base64'.", actualEncoding)
		log.Printf(errMsg)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: errMsg}},
		}, nil
	}

	// Ensure the directory exists
	dir := filepath.Dir(params.Arguments.Path)
	if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
		if mkdirErr := os.MkdirAll(dir, 0755); mkdirErr != nil {
			log.Printf("Error creating directory %s for file %s: %v", dir, params.Arguments.Path, mkdirErr)
			return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error creating directory %s: %v", dir, mkdirErr)}},
			}, nil
		}
	}


	flag := os.O_WRONLY | os.O_CREATE
	if params.Arguments.Append {
		flag |= os.O_APPEND
	} else {
		flag |= os.O_TRUNC // Overwrite: truncate if file exists
	}

	err = os.WriteFile(params.Arguments.Path, dataToWrite, 0644) // os.WriteFile handles create/truncate
	if params.Arguments.Append { // os.WriteFile truncates, so for append we need to open with append flag
		f, openErr := os.OpenFile(params.Arguments.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if openErr != nil {
			log.Printf("Error opening file %s for append: %v", params.Arguments.Path, openErr)
			return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error opening file %s for append: %v", params.Arguments.Path, openErr)}},
			}, nil
		}
		defer f.Close()
		if _, writeErr := f.Write(dataToWrite); writeErr != nil {
			log.Printf("Error appending to file %s: %v", params.Arguments.Path, writeErr)
			return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error appending to file %s: %v", params.Arguments.Path, writeErr)}},
			}, nil
		}
		err = nil // clear error from potential os.WriteFile if append was true
	} else { // Not appending, so os.WriteFile is fine
		err = os.WriteFile(params.Arguments.Path, dataToWrite, 0644)
	}


	if err != nil {
		log.Printf("Error writing file %s: %v", params.Arguments.Path, err)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error writing file %s: %v", params.Arguments.Path, err)}},
		}, nil
	}

	log.Printf("Successfully wrote file %s", params.Arguments.Path)
	msg := fmt.Sprintf("Successfully wrote to file %s", params.Arguments.Path)
	return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
		StructuredContent: &GenericSuccessFailureResult{Message: msg},
		Content:           []mcp.Content{&mcp.TextContent{Text: msg}},
	}, nil
}


// readFile implements the logic for the read_file tool.
func readFile(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[ReadFileArgs]) (*mcp.CallToolResultFor[ReadFileResult], error) {
	log.Printf("Received read_file request for path %s, encoding: %s", params.Arguments.Path, params.Arguments.Encoding)

	// TODO: Add security check for allowed read paths if necessary in the future.
	// For now, only write operations are restricted.

	contentBytes, err := os.ReadFile(params.Arguments.Path)
	if err != nil {
		log.Printf("Error reading file %s: %v", params.Arguments.Path, err)
		return &mcp.CallToolResultFor[ReadFileResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error reading file %s: %v", params.Arguments.Path, err)}},
		}, nil
	}

	var encodedContent string
	actualEncoding := params.Arguments.Encoding
	if actualEncoding == "" {
		actualEncoding = "utf-8" // Default to utf-8
	}


	switch actualEncoding {
	case "base64":
		encodedContent = base64.StdEncoding.EncodeToString(contentBytes)
	case "utf-8":
		encodedContent = string(contentBytes)
	default:
		errMsg := fmt.Sprintf("unsupported encoding: %s. Supported encodings are 'utf-8' and 'base64'.", params.Arguments.Encoding)
		log.Printf(errMsg)
		return &mcp.CallToolResultFor[ReadFileResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: errMsg}},
		}, nil
	}

	// Detect MIME type
	// http.DetectContentType needs at most 512 bytes
	var first512Bytes []byte
	if len(contentBytes) > 512 {
		first512Bytes = contentBytes[:512]
	} else {
		first512Bytes = contentBytes
	}
	mimeType := http.DetectContentType(first512Bytes)
	if mimeType == "application/octet-stream" && filepath.Ext(params.Arguments.Path) == ".md" {
		mimeType = "text/markdown" // Fix for markdown files often detected as octet-stream
	}


	log.Printf("Successfully read file %s, detected MIME type: %s", params.Arguments.Path, mimeType)
	result := &ReadFileResult{
		Content:  encodedContent,
		MimeType: mimeType,
	}
	// Provide a snippet of the content in TextContent for quick preview if it's not base64
	var textPreview string
	if params.Arguments.Encoding != "base64" {
		previewLen := 200
		if len(encodedContent) < previewLen {
			previewLen = len(encodedContent)
		}
		textPreview = fmt.Sprintf("Read file %s (MIME: %s). Content snippet:\n%s...", params.Arguments.Path, mimeType, encodedContent[:previewLen])
		if len(encodedContent) <= 200 {
			textPreview = fmt.Sprintf("Read file %s (MIME: %s). Content:\n%s", params.Arguments.Path, mimeType, encodedContent)
		}
	} else {
		textPreview = fmt.Sprintf("Read file %s (MIME: %s). Content is base64 encoded (length: %d chars).", params.Arguments.Path, mimeType, len(encodedContent))
	}

	return &mcp.CallToolResultFor[ReadFileResult]{
		StructuredContent: result,
		Content:           []mcp.Content{&mcp.TextContent{Text: textPreview}},
	}, nil
}

func listDirectoryRecursive(basePath string, currentPath string, items *[]FileSystemItem, recursive bool, maxDepth int, includeHidden bool, currentDepth int) error {
	if maxDepth > 0 && currentDepth >= maxDepth {
		return nil
	}

	files, err := os.ReadDir(currentPath)
	if err != nil {
		return fmt.Errorf("reading directory %s: %w", currentPath, err)
	}

	for _, file := range files {
		if !includeHidden && file.Name()[0] == '.' {
			continue
		}

		fullPath := fmt.Sprintf("%s/%s", currentPath, file.Name())
		info, err := file.Info()
		if err != nil {
			log.Printf("Could not get info for %s: %v", fullPath, err)
			continue // Skip files we can't get info for
		}

		itemType := "file"
		if info.IsDir() {
			itemType = "directory"
		}

		*items = append(*items, FileSystemItem{
			Name:         info.Name(),
			Type:         itemType,
			Size:         info.Size(),
			LastModified: info.ModTime(),
			Path:         fullPath,
		})

		if recursive && info.IsDir() {
			err := listDirectoryRecursive(basePath, fullPath, items, recursive, maxDepth, includeHidden, currentDepth+1)
			if err != nil {
				// Log error but continue listing other directories
				log.Printf("Error recursively listing directory %s: %v", fullPath, err)
			}
		}
	}
	return nil
}

// moveItem implements the logic for the move_item tool.
func moveItem(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[MoveItemArgs]) (*mcp.CallToolResultFor[GenericSuccessFailureResult], error) {
	log.Printf("Received move_item request from %s to %s", params.Arguments.SourcePath, params.Arguments.DestinationPath)

	opType := "move_item (source)"
	if err := isPathAllowed(params.Arguments.SourcePath, opType); err != nil {
		log.Printf("Access denied for %s on path %s: %v", opType, params.Arguments.SourcePath, err)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		}, nil
	}
	opType = "move_item (destination)"
	if err := isPathAllowed(params.Arguments.DestinationPath, opType); err != nil {
		log.Printf("Access denied for %s on path %s: %v", opType, params.Arguments.DestinationPath, err)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		}, nil
	}

	err := os.Rename(params.Arguments.SourcePath, params.Arguments.DestinationPath)
	if err != nil {
		log.Printf("Error moving item from %s to %s: %v", params.Arguments.SourcePath, params.Arguments.DestinationPath, err)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error moving item: %v", err)}},
		}, nil
	}
	msg := fmt.Sprintf("Successfully moved item from %s to %s", params.Arguments.SourcePath, params.Arguments.DestinationPath)
	return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
		StructuredContent: &GenericSuccessFailureResult{Message: msg},
		Content:           []mcp.Content{&mcp.TextContent{Text: msg}},
	}, nil
}

// getItemProperties implements the logic for the get_item_properties tool.
func getItemProperties(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[GetItemPropertiesArgs]) (*mcp.CallToolResultFor[ItemProperties], error) {
	log.Printf("Received get_item_properties request for path %s", params.Arguments.Path)

	info, err := os.Stat(params.Arguments.Path)
	if err != nil {
		log.Printf("Error getting properties for %s: %v", params.Arguments.Path, err)
		return &mcp.CallToolResultFor[ItemProperties]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error getting properties for %s: %v", params.Arguments.Path, err)}},
		}, nil
	}

	itemType := "file"
	if info.IsDir() {
		itemType = "directory"
	}

	// CreatedAt is platform-dependent. We'll try to get it, but it might not always be available or accurate.
	// On Unix systems, Stat_t's Ctim field might be used, but it's not directly exposed in a portable way in Go's os.FileInfo.
	// For simplicity, we'll use ModTime as a stand-in if a true creation time isn't easily accessible.
	// More sophisticated methods would require platform-specific calls or cgo.
	createdAt := info.ModTime() // Placeholder, actual creation time is hard to get portably.

	// CreatedAt will use info.ModTime() for broad compatibility as true creation time is hard to get portably.

	// Permissions
	permissions := info.Mode().String()

	// IsReadOnly - this is a simplified check.
	// For files, we attempt to open for writing.
	// For directories, we check the write permission bit for the user.
	isReadOnly := false // Assume writable by default, prove otherwise
	if info.IsDir() {
		if info.Mode().Perm()&0200 == 0 { // Check if User's write bit (UGO order: User, Group, Other) is NOT set
			isReadOnly = true
		}
	} else { // It's a file
		file, openErr := os.OpenFile(params.Arguments.Path, os.O_WRONLY, 0)
		if openErr != nil {
			if os.IsPermission(openErr) {
				isReadOnly = true
			}
			// If openErr is not nil but also not a permission error,
			// it means the file might be writable but there's another issue (e.g., already open exclusively).
			// In this specific check for "read-only due to permissions", we only set isReadOnly=true on os.IsPermission.
		} else {
			// Successfully opened for writing, so it's not read-only.
			file.Close() // Close immediately
			isReadOnly = false
		}
	}

	props := &ItemProperties{
		Name:         info.Name(),
		Path:         params.Arguments.Path, // Return the full path requested
		Type:         itemType,
		Size:         info.Size(),
		LastModified: info.ModTime(),
		CreatedAt:    createdAt, // As determined above
		Permissions:  permissions,
		IsReadOnly:   isReadOnly,
	}
	textContent := fmt.Sprintf("Properties for %s:\nType: %s\nSize: %d bytes\nModified: %s\nPermissions: %s\nRead-Only: %t",
		props.Path, props.Type, props.Size, props.LastModified.Format(time.RFC3339), props.Permissions, props.IsReadOnly)

	return &mcp.CallToolResultFor[ItemProperties]{
		StructuredContent: props,
		Content:           []mcp.Content{&mcp.TextContent{Text: textContent}},
	}, nil
}


// copyItem implements the logic for the copy_item tool.
func copyItem(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[CopyItemArgs]) (*mcp.CallToolResultFor[GenericSuccessFailureResult], error) {
	log.Printf("Received copy_item request from %s to %s, overwrite: %t", params.Arguments.SourcePath, params.Arguments.DestinationPath, params.Arguments.Overwrite)

	opType := "copy_item (destination)"
	if err := isPathAllowed(params.Arguments.DestinationPath, opType); err != nil {
		log.Printf("Access denied for %s on path %s: %v", opType, params.Arguments.DestinationPath, err)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		}, nil
	}

	err := copyPath(params.Arguments.SourcePath, params.Arguments.DestinationPath, params.Arguments.Overwrite)
	if err != nil {
		log.Printf("Error copying item from %s to %s: %v", params.Arguments.SourcePath, params.Arguments.DestinationPath, err)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error copying item: %v", err)}},
		}, nil
	}
	msg := fmt.Sprintf("Successfully copied item from %s to %s", params.Arguments.SourcePath, params.Arguments.DestinationPath)
	return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
		StructuredContent: &GenericSuccessFailureResult{Message: msg},
		Content:           []mcp.Content{&mcp.TextContent{Text: msg}},
	}, nil
}

func copyPath(src, dst string, overwrite bool) error {
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("source path error: %w", err)
	}

	if !overwrite {
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			return fmt.Errorf("destination path %s already exists and overwrite is false", dst)
		}
	}

	if sourceInfo.IsDir() {
		return copyDir(src, dst, overwrite)
	}
	return copyFile(src, dst, overwrite)
}

func copyFile(src, dst string, overwrite bool) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening source file %s: %w", src, err)
	}
	defer sourceFile.Close()

	// Ensure destination directory exists
	dstDir := filepath.Dir(dst)
	if _, err := os.Stat(dstDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dstDir, 0755); err != nil {
			return fmt.Errorf("creating destination directory %s: %w", dstDir, err)
		}
	}


	destFile, err := os.Create(dst) // Creates or truncates
	if err != nil {
		return fmt.Errorf("creating destination file %s: %w", dst, err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("copying content from %s to %s: %w", src, dst, err)
	}

	sourceInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat source file %s: %w", src, err)
	}
	return os.Chmod(dst, sourceInfo.Mode())
}

func copyDir(src, dst string, overwrite bool) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("creating destination directory %s: %w", dst, err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("reading source directory %s: %w", src, err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath, overwrite); err != nil {
				// Log or collect errors if you want to continue copying other files/dirs
				return fmt.Errorf("copying subdirectory %s to %s: %w", srcPath, dstPath, err)
			}
		} else {
			// Check if file is a symlink - os.ReadDir and entry.IsDir() won't tell you directly
			// Need to lstat the source path.
			fileInfo, err := os.Lstat(srcPath)
			if err != nil {
				return fmt.Errorf("lstat source item %s: %w", srcPath, err)
			}

			if fileInfo.Mode()&os.ModeSymlink != 0 {
				linkTarget, err := os.Readlink(srcPath)
				if err != nil {
					return fmt.Errorf("reading symlink %s: %w", srcPath, err)
				}
				if err := os.Symlink(linkTarget, dstPath); err != nil {
					return fmt.Errorf("creating symlink from %s to %s (target %s): %w", srcPath, dstPath, linkTarget, err)
				}
			} else {
				if err := copyFile(srcPath, dstPath, overwrite); err != nil {
					// Log or collect errors
					return fmt.Errorf("copying file %s to %s: %w", srcPath, dstPath, err)
				}
			}
		}
	}
	return nil
}

// extractArchive implements the logic for the extract_archive tool.
func extractArchive(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[ExtractArchiveArgs]) (*mcp.CallToolResultFor[GenericSuccessFailureResult], error) {
	log.Printf("Received extract_archive request for archive %s to destination %s, format %s", params.Arguments.ArchivePath, params.Arguments.DestinationPath, params.Arguments.Format)

	opType := "extract_archive (destination)"
	if err := isPathAllowed(params.Arguments.DestinationPath, opType); err != nil {
		log.Printf("Access denied for %s on path %s: %v", opType, params.Arguments.DestinationPath, err)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		}, nil
	}

	file, err := os.Open(params.Arguments.ArchivePath)
	if err != nil {
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error opening archive file %s: %v", params.Arguments.ArchivePath, err)}}}, nil
	}
	defer file.Close()

	format := params.Arguments.Format
	if format == "" {
		// Auto-detect format (simple version based on extension)
		if strings.HasSuffix(strings.ToLower(params.Arguments.ArchivePath), ".zip") {
			format = "zip"
		} else if strings.HasSuffix(strings.ToLower(params.Arguments.ArchivePath), ".tar.gz") || strings.HasSuffix(strings.ToLower(params.Arguments.ArchivePath), ".tgz") {
			format = "tar.gz"
		} else {
			return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
				IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Could not auto-detect archive format for %s. Please specify 'zip' or 'tar.gz'.", params.Arguments.ArchivePath)}}}, nil
		}
		log.Printf("Auto-detected format as: %s", format)
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(params.Arguments.DestinationPath, 0755); err != nil {
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error creating destination directory %s: %v", params.Arguments.DestinationPath, err)}}}, nil
	}


	switch format {
	case "zip":
		err = extractZipArchive(file, params.Arguments.DestinationPath)
	case "tar.gz":
		err = extractTarGzArchive(file, params.Arguments.DestinationPath)
	default:
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Unsupported archive format: %s. Supported are 'zip', 'tar.gz'.", format)}}}, nil
	}

	if err != nil {
		log.Printf("Error extracting archive %s: %v", params.Arguments.ArchivePath, err)
		// Note: No attempt to clean up partially extracted files here, as it could be complex and risky.
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error extracting archive: %v", err)}}}, nil
	}

	log.Printf("Successfully extracted archive %s to %s", params.Arguments.ArchivePath, params.Arguments.DestinationPath)
	msg := fmt.Sprintf("Successfully extracted archive %s to %s", params.Arguments.ArchivePath, params.Arguments.DestinationPath)
	return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
		StructuredContent: &GenericSuccessFailureResult{Message: msg},
		Content:           []mcp.Content{&mcp.TextContent{Text: msg}},
	}, nil
}


func extractZipArchive(archiveFile *os.File, destinationPath string) error {
	stat, err := archiveFile.Stat()
	if err != nil {
		return fmt.Errorf("stat archive file: %w", err)
	}

	zipReader, err := zip.NewReader(archiveFile, stat.Size())
	if err != nil {
		return fmt.Errorf("creating zip reader: %w", err)
	}

	for _, file := range zipReader.File {
		// Sanitize file.Name to prevent leading slashes or ".." that could cause issues with filepath.Join
		// and ensure it's treated as a relative path component.
		cleanedName := filepath.Clean(file.Name)
		if strings.HasPrefix(cleanedName, ".."+string(os.PathSeparator)) || strings.HasPrefix(cleanedName, "/") || strings.HasPrefix(cleanedName, "\\"){
			return fmt.Errorf("invalid file name in zip (potential path traversal): %s", file.Name)
		}
		filePath := filepath.Join(destinationPath, cleanedName)


		// Security check: Ensure the constructed path is still within the destination directory.
		absDestPath, _ := filepath.Abs(destinationPath)
		absFilePath, _ := filepath.Abs(filePath)
		if !strings.HasPrefix(absFilePath, absDestPath) {
			return fmt.Errorf("invalid file path in archive (path traversal attempt): %s", file.Name)
		}


		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, file.Mode()); err != nil {
				return fmt.Errorf("creating directory %s from zip: %w", filePath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return fmt.Errorf("creating parent directory for %s from zip: %w", filePath, err)
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return fmt.Errorf("creating file %s from zip: %w", filePath, err)
		}

		srcFile, err := file.Open()
		if err != nil {
			dstFile.Close()
			return fmt.Errorf("opening file %s in zip: %w", file.Name, err)
		}

		_, err = io.Copy(dstFile, srcFile)
		closeErrDst := dstFile.Close()
		closeErrSrc := srcFile.Close()

		if err != nil {
			return fmt.Errorf("copying content for %s from zip: %w", file.Name, err)
		}
		if closeErrDst != nil {
			return fmt.Errorf("closing destination file %s from zip: %w", filePath, closeErrDst)
		}
		if closeErrSrc != nil {
			return fmt.Errorf("closing source file %s in zip: %w", file.Name, closeErrSrc)
		}
	}
	return nil
}

func extractTarGzArchive(archiveFile *os.File, destinationPath string) error {
	gzipReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		// If opening as .tar.gz fails, it might be an uncompressed .tar file. Try that.
		// Reset read pointer of the original file.
		if _, seekErr := archiveFile.Seek(0, io.SeekStart); seekErr != nil {
			return fmt.Errorf("seeking archive file to retry as tar: %w", seekErr)
		}
		return extractTarArchive(archiveFile, destinationPath) // Try plain tar
	}
	// Proceed with gzipReader if successful
	defer gzipReader.Close()
	return extractTarArchive(gzipReader, destinationPath) // Pass the gzipReader to a common tar extraction logic
}

func extractTarArchive(r io.Reader, destinationPath string) error { // Takes io.Reader for flexibility
	tarReader := tar.NewReader(r)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("reading tar header: %w", err)
		}

		cleanedName := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanedName, ".."+string(os.PathSeparator)) || strings.HasPrefix(cleanedName, "/") || strings.HasPrefix(cleanedName, "\\"){
			return fmt.Errorf("invalid file name in tar (potential path traversal): %s", header.Name)
		}
		targetPath := filepath.Join(destinationPath, cleanedName)

		absDestPath, _ := filepath.Abs(destinationPath)
		absTargetPath, _ := filepath.Abs(targetPath)
		if !strings.HasPrefix(absTargetPath, absDestPath) {
			return fmt.Errorf("invalid file path in archive (path traversal attempt): %s", header.Name)
		}


		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("creating directory %s from tar: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("creating parent directory for %s from tar: %w", targetPath, err)
			}

			outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("creating file %s from tar: %w", targetPath, err)
			}

			_, copyErr := io.Copy(outFile, tarReader)
			closeErr := outFile.Close()

			if copyErr != nil {
				return fmt.Errorf("copying content for %s from tar: %w", header.Name, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("closing file %s from tar: %w", targetPath, closeErr)
			}

		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("creating parent directory for symlink %s: %w", targetPath, err)
			}
			// Security: validate header.Linkname as well. It should not point outside destinationPath.
			// This is complex because Linkname can be absolute or relative.
			// A simple check: if Linkname is absolute, it must be within destinationPath.
			// If relative, the resolved path (targetPath + Linkname) must be within.
			// For now, we proceed with a basic symlink creation.
			// Production systems need very careful symlink handling during extraction.
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				// Check if linkname is absolute and outside bounds
				if filepath.IsAbs(header.Linkname) {
					absLinkName, _ := filepath.Abs(header.Linkname)
					if !strings.HasPrefix(absLinkName, absDestPath){
						return fmt.Errorf("symlink %s in tar points to %s, which is outside extraction destination", header.Name, header.Linkname)
					}
				} else { // Relative link
					resolvedLinkPath := filepath.Join(filepath.Dir(targetPath), header.Linkname)
					absResolvedLinkPath, _ := filepath.Abs(resolvedLinkPath)
					if !strings.HasPrefix(absResolvedLinkPath, absDestPath) {
						return fmt.Errorf("symlink %s in tar resolves to %s, which is outside extraction destination", header.Name, resolvedLinkPath)
					}
				}
				// If the above checks didn't trigger, but Symlink still failed, return that error.
				return fmt.Errorf("creating symlink %s -> %s from tar: %w", targetPath, header.Linkname, err)
			}


		default:
			log.Printf("Unsupported tar entry type %c for %s", header.Typeflag, header.Name)
		}
	}
	return nil
}

// deleteItem implements the logic for the delete_item tool.
func deleteItem(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[DeleteItemArgs]) (*mcp.CallToolResultFor[GenericSuccessFailureResult], error) {
	log.Printf("Received delete_item request for path %s, recursive: %t", params.Arguments.Path, params.Arguments.Recursive)

	opType := "delete_item"
	if err := isPathAllowed(params.Arguments.Path, opType); err != nil {
		log.Printf("Access denied for %s on path %s: %v", opType, params.Arguments.Path, err)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		}, nil
	}

	info, err := os.Stat(params.Arguments.Path)
	if err != nil {
		if os.IsNotExist(err) {
			// Comply with expected behavior: if it doesn't exist, it's a success for delete.
			// Or, return an error? User expectation might vary. For now, let's consider it not an error.
			// If this needs to be an error, the IsError flag and Content should be set accordingly.
			log.Printf("Path %s does not exist, considering delete successful.", params.Arguments.Path)
			msg := fmt.Sprintf("Item %s did not exist or was already deleted.", params.Arguments.Path)
			return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
				StructuredContent: &GenericSuccessFailureResult{Message: msg},
				Content:           []mcp.Content{&mcp.TextContent{Text: msg}},
			}, nil
		}
		// For other errors (e.g., permission denied to stat), return an error.
		log.Printf("Error stating item %s: %v", params.Arguments.Path, err)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error accessing item %s: %v", params.Arguments.Path, err)}},
		}, nil
	}

	if info.IsDir() && !params.Arguments.Recursive {
		// Check if directory is empty if not recursive
		dirEntries, readDirErr := os.ReadDir(params.Arguments.Path)
		if readDirErr != nil {
			log.Printf("Error reading directory %s to check if empty: %v", params.Arguments.Path, readDirErr)
			return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error reading directory %s: %v", params.Arguments.Path, readDirErr)}},
			}, nil
		}
		if len(dirEntries) > 0 {
			errMsg := fmt.Sprintf("directory %s is not empty and recursive is false", params.Arguments.Path)
			log.Printf(errMsg)
			return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: errMsg}},
			}, nil
		}
	}

	var delErr error
	if info.IsDir() && params.Arguments.Recursive {
		delErr = os.RemoveAll(params.Arguments.Path)
	} else {
		delErr = os.Remove(params.Arguments.Path) // Works for files and empty directories
	}

	if delErr != nil {
		log.Printf("Error deleting item %s: %v", params.Arguments.Path, delErr)
		return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error deleting item %s: %v", params.Arguments.Path, delErr)}},
		}, nil
	}

	log.Printf("Successfully deleted item %s", params.Arguments.Path)
	msg := fmt.Sprintf("Successfully deleted item %s", params.Arguments.Path)
	return &mcp.CallToolResultFor[GenericSuccessFailureResult]{
		StructuredContent: &GenericSuccessFailureResult{Message: msg},
		Content:           []mcp.Content{&mcp.TextContent{Text: msg}},
	}, nil
}

// createArchive implements the logic for the create_archive tool.
func createArchive(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[CreateArchiveArgs]) (*mcp.CallToolResultFor[CreateArchiveResult], error) {
	log.Printf("Received create_archive request for sources %v, archive path %s, format %s", params.Arguments.SourcePaths, params.Arguments.ArchivePath, params.Arguments.Format)

	opType := "create_archive"
	if err := isPathAllowed(params.Arguments.ArchivePath, opType); err != nil {
		log.Printf("Access denied for %s on path %s: %v", opType, params.Arguments.ArchivePath, err)
		return &mcp.CallToolResultFor[CreateArchiveResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		}, nil
	}

	if len(params.Arguments.SourcePaths) == 0 {
		return &mcp.CallToolResultFor[CreateArchiveResult]{
			IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "No source paths provided for archiving."}}}, nil
	}

	// Ensure destination directory for archive exists
	archiveDir := filepath.Dir(params.Arguments.ArchivePath)
	if _, err := os.Stat(archiveDir); os.IsNotExist(err) {
		if mkErr := os.MkdirAll(archiveDir, 0755); mkErr != nil {
			return &mcp.CallToolResultFor[CreateArchiveResult]{
				IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error creating directory for archive %s: %v", archiveDir, mkErr)}}}, nil
		}
	}


	outFile, err := os.Create(params.Arguments.ArchivePath)
	if err != nil {
		return &mcp.CallToolResultFor[CreateArchiveResult]{
			IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error creating archive file %s: %v", params.Arguments.ArchivePath, err)}}}, nil
	}
	defer outFile.Close()

	switch params.Arguments.Format {
	case "zip":
		err = createZipArchive(outFile, params.Arguments.SourcePaths)
	case "tar.gz":
		err = createTarGzArchive(outFile, params.Arguments.SourcePaths)
	default:
		return &mcp.CallToolResultFor[CreateArchiveResult]{
			IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Unsupported archive format: %s. Supported formats are 'zip', 'tar.gz'.", params.Arguments.Format)}}}, nil
	}

	if err != nil {
		// Attempt to remove partially created archive on error
		os.Remove(params.Arguments.ArchivePath)
		log.Printf("Error creating archive %s: %v", params.Arguments.ArchivePath, err)
		return &mcp.CallToolResultFor[CreateArchiveResult]{
			IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error creating archive: %v", err)}}}, nil
	}

	result := &CreateArchiveResult{PathToArchive: params.Arguments.ArchivePath}
	textContent := fmt.Sprintf("Successfully created archive %s", params.Arguments.ArchivePath)
	return &mcp.CallToolResultFor[CreateArchiveResult]{
		StructuredContent: result,
		Content:           []mcp.Content{&mcp.TextContent{Text: textContent}},
	}, nil
}

func createZipArchive(outFile *os.File, sourcePaths []string) error {
	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	for _, sourcePath := range sourcePaths {
		// Ensure source path is clean and absolute to handle relative paths correctly inside archive
		absSourcePath, err := filepath.Abs(sourcePath)
		if err != nil {
			return fmt.Errorf("failed to get absolute path for %s: %w", sourcePath, err)
		}

		info, err := os.Stat(absSourcePath)
		if err != nil {
			return fmt.Errorf("failed to stat source path %s: %w", absSourcePath, err)
		}

		basePath := filepath.Dir(absSourcePath)
		if !info.IsDir() {
			// If it's a single file, its "base" for archive path calculation is its own directory
			basePath = filepath.Dir(absSourcePath)
		} else {
			// If it's a directory, its contents will be relative to this directory path itself.
			// We want the archive to contain the directory itself, not just its contents.
			// So, the basePath for stripping from archive paths should be the parent of sourcePath.
			basePath = filepath.Dir(absSourcePath)
		}


		err = filepath.Walk(absSourcePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("error accessing path %s: %w", path, err)
			}

			// Create a relative path for the file/dir in the archive
			relPath, err := filepath.Rel(basePath, path)
			if err != nil {
				return fmt.Errorf("failed to get relative path for %s (base %s): %w", path, basePath, err)
			}

			// If we are archiving a single file, relPath would be just its name.
			// If we are archiving a directory, relPath would start with the directory's name.
			// If multiple top-level items are specified, this structure should be fine.

			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return fmt.Errorf("failed to create zip header for %s: %w", path, err)
			}

			header.Name = relPath // Use relative path
			if info.IsDir() {
				header.Name += "/" // Add trailing slash for directories
			}
			header.Method = zip.Deflate // Use compression

			writer, err := zipWriter.CreateHeader(header)
			if err != nil {
				return fmt.Errorf("failed to create entry in zip for %s: %w", relPath, err)
			}

			if !info.IsDir() {
				file, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("failed to open file %s for archiving: %w", path, err)
				}
				defer file.Close()
				_, err = io.Copy(writer, file)
				if err != nil {
					return fmt.Errorf("failed to copy file content to zip for %s: %w", path, err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("error walking path %s for zipping: %w", absSourcePath, err)
		}
	}
	return nil
}

func createTarGzArchive(outFile *os.File, sourcePaths []string) error {
	gzipWriter := gzip.NewWriter(outFile)
	defer gzipWriter.Close()
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	for _, sourcePath := range sourcePaths {
		absSourcePath, err := filepath.Abs(sourcePath)
		if err != nil {
			return fmt.Errorf("failed to get absolute path for %s: %w", sourcePath, err)
		}

		info, err := os.Stat(absSourcePath)
		if err != nil {
			return fmt.Errorf("failed to stat source path %s: %w", absSourcePath, err)
		}

		basePath := filepath.Dir(absSourcePath)
        if !info.IsDir() {
            basePath = filepath.Dir(absSourcePath)
        } else {
            basePath = filepath.Dir(absSourcePath)
        }


		err = filepath.Walk(absSourcePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("error accessing path %s: %w", path, err)
			}

			relPath, err := filepath.Rel(basePath, path)
			if err != nil {
				return fmt.Errorf("failed to get relative path for %s: %w", path, err)
			}

			header, err := tar.FileInfoHeader(info, "") // link argument is for symlinks, not used here
			if err != nil {
				return fmt.Errorf("failed to create tar header for %s: %w", path, err)
			}
			header.Name = relPath // Use relative path

			if err := tarWriter.WriteHeader(header); err != nil {
				return fmt.Errorf("failed to write tar header for %s: %w", path, err)
			}

			if !info.IsDir() {
				file, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("failed to open file %s for taring: %w", path, err)
				}
				defer file.Close()
				_, err = io.Copy(tarWriter, file)
				if err != nil {
					return fmt.Errorf("failed to copy file content to tar for %s: %w", path, err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("error walking path %s for taring: %w", absSourcePath, err)
		}
	}
	return nil
}


// itemExists implements the logic for the item_exists tool.
func itemExists(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[ItemExistsArgs]) (*mcp.CallToolResultFor[ItemExistsResult], error) {
	log.Printf("Received item_exists request for path %s", params.Arguments.Path)

	info, err := os.Stat(params.Arguments.Path)
	if err != nil {
		if os.IsNotExist(err) {
			result := &ItemExistsResult{Exists: false, Type: "not_found"}
			textContent := fmt.Sprintf("Item %s does not exist.", params.Arguments.Path)
			return &mcp.CallToolResultFor[ItemExistsResult]{
				StructuredContent: result,
				Content:           []mcp.Content{&mcp.TextContent{Text: textContent}},
			}, nil
		}
		// For other errors (e.g., permission denied), we can't determine existence for sure.
		// It's probably best to return an error in this case.
		log.Printf("Error checking existence for path %s: %v", params.Arguments.Path, err)
		return &mcp.CallToolResultFor[ItemExistsResult]{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error accessing path %s: %v", params.Arguments.Path, err)}},
		}, nil
	}

	itemType := "file"
	if info.IsDir() {
		itemType = "directory"
	}
	result := &ItemExistsResult{Exists: true, Type: itemType}
	textContent := fmt.Sprintf("Item %s exists. Type: %s.", params.Arguments.Path, itemType)
	return &mcp.CallToolResultFor[ItemExistsResult]{
		StructuredContent: result,
		Content:           []mcp.Content{&mcp.TextContent{Text: textContent}},
	}, nil
}


// applyFilesystemManifest implements the logic for the apply_filesystem_manifest tool.
func applyFilesystemManifest(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[ApplyFilesystemManifestArgs]) (*mcp.CallToolResultFor[any], error) {
	log.Printf("Received apply_filesystem_manifest request with %d operations", len(params.Arguments.Operations))
	for _, op := range params.Arguments.Operations {
		log.Printf("Processing operation: Type=%s, Path=%s", op.Type, op.Path)

		// Check path allowance for write operations
		if op.Type == "create_directory" || op.Type == "create_file" {
			if err := isPathAllowed(op.Path, op.Type); err != nil {
				log.Printf("Access denied for operation %s on path %s: %v", op.Type, op.Path, err)
				return &mcp.CallToolResultFor[any]{
					IsError: true,
					Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
				}, nil
			}
		}

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

	// Adding the new tools
	server.AddTools(
		// list_directory
		mcp.NewServerTool(
			"list_directory",
			"Lists directory contents with options for recursion, depth, and hidden files.",
			listDirectory,
			mcp.Input(
				mcp.Property("path", mcp.Description("Directory path to list."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("recursive", mcp.Description("List recursively."), mcp.Schema(&jsonschema.Schema{Type: "boolean", Default: false})),
				mcp.Property("max_depth", mcp.Description("Maximum depth for recursion."), mcp.Schema(&jsonschema.Schema{Type: "integer", Default: 0})),
				mcp.Property("include_hidden", mcp.Description("Include hidden files/directories."), mcp.Schema(&jsonschema.Schema{Type: "boolean", Default: false})),
			),
			// Output schema for ListDirectoryResult will be implicitly derived from the struct + Result field.
		),
		// move_item
		mcp.NewServerTool(
			"move_item",
			"Moves or renames a file or directory.",
			moveItem,
			mcp.Input(
				mcp.Property("source_path", mcp.Description("Source path of the item to move."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("destination_path", mcp.Description("Destination path for the item."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
			),
		),
		// copy_item
		mcp.NewServerTool(
			"copy_item",
			"Copies a file or directory.",
			copyItem,
			mcp.Input(
				mcp.Property("source_path", mcp.Description("Source path of the item to copy."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("destination_path", mcp.Description("Destination path for the copy."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("overwrite", mcp.Description("Overwrite destination if it exists."), mcp.Schema(&jsonschema.Schema{Type: "boolean", Default: false})),
			),
		),
		// delete_item
		mcp.NewServerTool(
			"delete_item",
			"Deletes a file or directory.",
			deleteItem,
			mcp.Input(
				mcp.Property("path", mcp.Description("Path of the item to delete."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("recursive", mcp.Description("Delete recursively (for directories)."), mcp.Schema(&jsonschema.Schema{Type: "boolean", Default: false})),
			),
		),
		// read_file
		mcp.NewServerTool(
			"read_file",
			"Reads file content.",
			readFile,
			mcp.Input(
				mcp.Property("path", mcp.Description("Path of the file to read."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("encoding", mcp.Description("Encoding for the output content ('utf-8' or 'base64'). Defaults to 'utf-8'."), mcp.Schema(&jsonschema.Schema{Type: "string", Enum: []any{"utf-8", "base64"}})),
			),
		),
		// write_file
		mcp.NewServerTool(
			"write_file",
			"Writes content to a file, creating it if it doesn't exist.",
			writeFile,
			mcp.Input(
				mcp.Property("path", mcp.Description("Path of the file to write."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("content", mcp.Description("Content to write."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("append", mcp.Description("Append to the file if it exists, otherwise overwrite."), mcp.Schema(&jsonschema.Schema{Type: "boolean", Default: false})),
				mcp.Property("encoding", mcp.Description("Encoding of the input content ('utf-8' or 'base64'). Assumes 'utf-8' if not specified."), mcp.Schema(&jsonschema.Schema{Type: "string", Enum: []any{"utf-8", "base64"}})),
			),
		),
		// get_item_properties
		mcp.NewServerTool(
			"get_item_properties",
			"Gets detailed properties of a file or directory.",
			getItemProperties,
			mcp.Input(
				mcp.Property("path", mcp.Description("Path of the item to get properties for."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
			),
		),
		// item_exists
		mcp.NewServerTool(
			"item_exists",
			"Checks if a file or directory exists.",
			itemExists,
			mcp.Input(
				mcp.Property("path", mcp.Description("Path to check for existence."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
			),
		),
		// create_archive
		mcp.NewServerTool(
			"create_archive",
			"Creates an archive (zip or tar.gz) from specified source paths.",
			createArchive,
			mcp.Input(
				mcp.Property("source_paths", mcp.Description("Array of file/directory paths to archive."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "array", Items: &jsonschema.Schema{Type: "string"}})),
				mcp.Property("archive_path", mcp.Description("Path for the output archive file."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("format", mcp.Description("Archive format ('zip' or 'tar.gz')."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string", Enum: []any{"zip", "tar.gz"}})),
			),
		),
		// extract_archive
		mcp.NewServerTool(
			"extract_archive",
			"Extracts an archive to a specified destination.",
			extractArchive,
			mcp.Input(
				mcp.Property("archive_path", mcp.Description("Path of the archive file to extract."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("destination_path", mcp.Description("Directory where the archive contents will be extracted."), mcp.Required(true), mcp.Schema(&jsonschema.Schema{Type: "string"})),
				mcp.Property("format", mcp.Description("Archive format ('zip' or 'tar.gz'). Optional, will try to auto-detect from extension if not provided."), mcp.Schema(&jsonschema.Schema{Type: "string", Enum: []any{"", "zip", "tar.gz"}})),
			),
		),
	)

	// Run the server over stdin/stdout, until the client disconnects.
	if err := server.Run(context.Background(), mcp.NewStdioTransport()); err != nil {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Filesystem MCP server stopped.")
}

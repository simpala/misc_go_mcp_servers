# File System Utilities MCP Server

This directory contains a Model Context Protocol (MCP) server that provides a suite of tools for file and directory manipulation. It allows an MCP client to perform various filesystem operations on the machine where the server is running, subject to specified security restrictions.

## Features

*   **Comprehensive File Operations**: Create, read, write, copy, move, and delete files and directories.
*   **Directory Listing**: List directory contents with options for recursion, depth control, and visibility of hidden files.
*   **File Properties**: Retrieve detailed metadata for files and directories, including size, modification times, permissions, and type.
*   **Archive Management**: Create and extract ZIP and TAR.GZ archives.
*   **Security**: Restrict write operations to designated directories using the `--allowed-dirs` flag.

## Building the Server

To build the server, ensure you have Go installed. Navigate to the `filesys_utils` directory and run:

```bash
go build -o filesys_mcp_server main.go
```

This will create an executable named `filesys_mcp_server` (or `filesys_mcp_server.exe` on Windows).

## Running the Server

Execute the compiled binary. For security, it is crucial to use the `--allowed-dirs` flag to specify which directories the server is permitted to write to.

```bash
./filesys_mcp_server --allowed-dirs /path/to/safe/sandbox1 --allowed-dirs /path/to/another/safe/area
```

*   `--allowed-dirs`: Specifies a directory where write operations (create, write, copy, move, delete, extract) are permitted. This flag can be used multiple times to allow multiple directories.
    *   **Security Warning**: If this flag is **not** provided, the server defaults to allowing write operations only within its current working directory (CWD) at the time of startup. It is strongly recommended to always explicitly define `--allowed-dirs` for production or sensitive environments.
*   The server listens for MCP requests on standard input (stdin) and sends responses to standard output (stdout).

## Available Tools

The server exposes the following tools to MCP clients:

1.  **`apply_filesystem_manifest`**:
    *   Description: Applies a manifest of filesystem operations (create_directory, create_file). This is a batch operation tool.
    *   Arguments: `operations` (array of objects, each with `type`, `path`, and optional `content`).
2.  **`list_directory`**:
    *   Description: Lists directory contents.
    *   Arguments: `path` (string, required), `recursive` (boolean), `max_depth` (integer), `include_hidden` (boolean).
3.  **`move_item`**:
    *   Description: Moves or renames a file or directory.
    *   Arguments: `source_path` (string, required), `destination_path` (string, required).
4.  **`copy_item`**:
    *   Description: Copies a file or directory.
    *   Arguments: `source_path` (string, required), `destination_path` (string, required), `overwrite` (boolean).
5.  **`delete_item`**:
    *   Description: Deletes a file or directory.
    *   Arguments: `path` (string, required), `recursive` (boolean, required for non-empty directories).
6.  **`read_file`**:
    *   Description: Reads file content.
    *   Arguments: `path` (string, required), `encoding` (string, 'utf-8' or 'base64').
    *   Output: File content (string), detected MIME type (string).
7.  **`write_file`**:
    *   Description: Writes content to a file, creating it if it doesn't exist.
    *   Arguments: `path` (string, required), `content` (string, required), `append` (boolean), `encoding` (string, 'utf-8' or 'base64' for input content).
8.  **`get_item_properties`**:
    *   Description: Gets detailed properties of a file or directory.
    *   Arguments: `path` (string, required).
    *   Output: Object with name, path, type, size, last_modified, created_at, permissions, is_readonly.
9.  **`item_exists`**:
    *   Description: Checks if a file or directory exists.
    *   Arguments: `path` (string, required).
    *   Output: `exists` (boolean), `type` (string: 'file', 'directory', or 'not_found').
10. **`create_archive`**:
    *   Description: Creates an archive (zip or tar.gz) from specified source paths.
    *   Arguments: `source_paths` (array of strings, required), `archive_path` (string, required), `format` (string: 'zip' or 'tar.gz', required).
11. **`extract_archive`**:
    *   Description: Extracts an archive to a specified destination.
    *   Arguments: `archive_path` (string, required), `destination_path` (string, required), `format` (string: 'zip' or 'tar.gz', optional, auto-detects if omitted).

## Client Interaction Example

You can interact with this MCP server using an MCP client that communicates over stdio. An example client (`std_io_json_client.go`) is available in the `mcp_client` directory of the parent repository.

1.  **Start the server**:
    ```bash
    ./filesys_mcp_server --allowed-dirs ./my_sandbox
    ```
    (Ensure `./my_sandbox` directory exists or the server has permission to create it if operations target it directly).

2.  **Prepare a JSON payload** for the client (e.g., `payload.json`):
    ```json
    [
      {
        "id": "list_sandbox",
        "tool_name": "list_directory",
        "arguments": {
          "path": "my_sandbox",
          "recursive": false
        }
      },
      {
        "id": "create_test_file",
        "tool_name": "write_file",
        "arguments": {
          "path": "my_sandbox/example.txt",
          "content": "Hello from MCP!"
        }
      }
    ]
    ```

3.  **Run the client** (assuming `mcp_client` is in the parent directory):
    ```bash
    go run ../mcp_client/std_io_json_client.go < payload.json
    ```

The client will send the requests from `payload.json` to the server, and the server's responses (tool results or errors) will be printed to the client's stdout. You can then inspect the `./my_sandbox` directory to see the effects of the `write_file` operation.

Refer to `test_payload_extended.json` in this directory for more examples of tool calls.
---

This MCP server is a powerful tool. Always ensure it is run with appropriate `--allowed-dirs` restrictions to prevent unintended or malicious file system modifications.

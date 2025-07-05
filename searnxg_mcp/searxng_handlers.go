package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	md "github.com/JohannesKaufmann/html-to-markdown"
	"github.com/JohannesKaufmann/html-to-markdown/plugin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	// "github.com/modelcontextprotocol/go-sdk/mcp" // This can be removed if not used elsewhere
)

const defaultSearxngURL = "http://localhost:8080"

// SearxngAPIResponse is a more comprehensive struct for the whole SearXNG JSON response.
type SearxngAPIResponse struct {
	Query               string          `json:"query"`
	Results             []SearxngResult `json:"results"`
	Answers             []string        `json:"answers"`
	Corrections         []string        `json:"corrections"`
	Infoboxes           []Infobox       `json:"infoboxes"`
	Suggestions         []string        `json:"suggestions"`
	UnresponsiveEngines [][]string      `json:"unresponsive_engines"` // [engine_name, error_message]
	NumberOfResults     *int            `json:"number_of_results,omitempty"`
}

// Infobox defines the structure for infoboxes in SearXNG results.
type Infobox struct {
	Infobox string `json:"infobox"`
	Content string `json:"content"`
	Engine  string `json:"engine"`
	URL     string `json:"url"`
}

func getSearxngURL() string {
	envURL := os.Getenv("SEARXNG_URL")
	if envURL == "" {
		return defaultSearxngURL
	}
	return envURL
}

func searxngWebSearchHandler(ctx context.Context, ss *mcp.ServerSession, params *mcp.CallToolParamsFor[SearxngWebSearchInput]) (*mcp.CallToolResultFor[SearxngWebSearchOutput], error) {
	input := params.Arguments
	if input.Query == "" {
		return nil, fmt.Errorf("search query cannot be empty")
	}

	apiURL := getSearxngURL()
	if !strings.HasSuffix(apiURL, "/") {
		apiURL += "/"
	}

	queryParams := url.Values{}
	queryParams.Set("q", input.Query)
	queryParams.Set("format", "json")

	if input.PageNo != nil && *input.PageNo > 0 {
		queryParams.Set("pageno", strconv.Itoa(*input.PageNo))
	}
	if input.TimeRange != nil && *input.TimeRange != "" {
		queryParams.Set("time_range", *input.TimeRange)
	}
	if input.Language != nil && *input.Language != "" {
		queryParams.Set("languages", *input.Language)
	}
	if input.SafeSearch != nil {
		queryParams.Set("safesearch", strconv.Itoa(*input.SafeSearch))
	}

	queryParams.Set("categories", "general")

	fullURL := apiURL + "?" + queryParams.Encode()
	if ss != nil {
		ss.Log(ctx, &mcp.LoggingMessageParams{Level: "debug", Data: fmt.Sprintf("Calling SearXNG: %s", fullURL)})
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SearXNG request: %w", err)
	}

	authUsername := os.Getenv("AUTH_USERNAME")
	authPassword := os.Getenv("AUTH_PASSWORD")
	if authUsername != "" && authPassword != "" {
		req.SetBasicAuth(authUsername, authPassword)
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute SearXNG request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SearXNG request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var searxngResp SearxngAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&searxngResp); err != nil {
		return nil, fmt.Errorf("failed to decode SearXNG JSON response: %w", err)
	}

	output := SearxngWebSearchOutput{
		Results: searxngResp.Results,
		Query:   searxngResp.Query,
	}
	if searxngResp.NumberOfResults != nil {
		output.NumberOfResults = *searxngResp.NumberOfResults
	}
	if input.PageNo != nil {
		output.CurrentPage = input.PageNo
	}

	var textResults []string
	for i, res := range output.Results {
		if i < 5 {
			textResults = append(textResults, fmt.Sprintf("%d. %s\n   %s\n   %s", i+1, res.Title, res.URL, res.Content))
		}
	}
	textContent := strings.Join(textResults, "\n---\n")
	if len(output.Results) > 5 {
		textContent += fmt.Sprintf("\n... and %d more results.", len(output.Results)-5)
	}
	if len(output.Results) == 0 {
		textContent = "No results found."
	}

	return &mcp.CallToolResultFor[SearxngWebSearchOutput]{
		Content: []mcp.Content{
			&mcp.TextContent{Text: textContent},
		},
		StructuredContent: output,
	}, nil
}

func webURLReadHandler(ctx context.Context, ss *mcp.ServerSession, params *mcp.CallToolParamsFor[WebURLReadInput]) (*mcp.CallToolResultFor[WebURLReadOutput], error) {
	input := params.Arguments
	if input.URL == "" {
		return nil, fmt.Errorf("URL cannot be empty")
	}

	if ss != nil {
		ss.Log(ctx, &mcp.LoggingMessageParams{Level: "debug", Data: fmt.Sprintf("Fetching URL: %s", input.URL)})
	}

	req, err := http.NewRequestWithContext(ctx, "GET", input.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for URL %s: %w", input.URL, err)
	}
	req.Header.Set("User-Agent", "MCP-Searxng-Go-Client/1.0")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL %s: %w", input.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch URL %s with status %d", input.URL, resp.StatusCode)
	}

	htmlBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from %s: %w", input.URL, err)
	}

	converter := md.NewConverter("", true, nil)
	converter.Use(plugin.AbsoluteLinks(input.URL))

	markdown, err := converter.ConvertString(string(htmlBody))
	if err != nil {
		return nil, fmt.Errorf("failed to convert HTML to Markdown for %s: %w", input.URL, err)
	}

	title := ""
	if submatch := titleRegex.FindStringSubmatch(string(htmlBody)); len(submatch) > 1 {
		title = submatch[1]
	}

	output := WebURLReadOutput{
		MarkdownContent: markdown,
		URL:             input.URL,
		Title:           title,
	}

	return &mcp.CallToolResultFor[WebURLReadOutput]{
		Content: []mcp.Content{
			&mcp.TextContent{Text: markdown},
		},
		StructuredContent: output,
	}, nil
}

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

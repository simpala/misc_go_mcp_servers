package main

// SearxngWebSearchInput defines the input parameters for the searxng_web_search tool.
type SearxngWebSearchInput struct {
	Query      string `json:"query"`
	PageNo     *int   `json:"pageno,omitempty"`     // Optional: Search page number, starts at 1 (default 1)
	TimeRange  *string `json:"time_range,omitempty"` // Optional: Filter results by time range - one of: "day", "month", "year" (default: none)
	Language   *string `json:"language,omitempty"`   // Optional: Language code for results (e.g., "en", "fr", "de") or "all" (default: "all")
	SafeSearch *int   `json:"safesearch,omitempty"` // Optional: Safe search filter level (0: None, 1: Moderate, 2: Strict) (default: instance setting)
}

// WebURLReadInput defines the input parameters for the web_url_read tool.
type WebURLReadInput struct {
	URL string `json:"url"`
}

// SearxngResult defines the structure for a single search result from SearXNG.
// This is a simplified version based on common SearXNG output.
// We might need to adjust this based on the actual JSON structure from a SearXNG instance.
type SearxngResult struct {
	URL         string   `json:"url"`
	Title       string   `json:"title"`
	Content     string   `json:"content,omitempty"`
	PublishedDate *string `json:"publishedDate,omitempty"` // Make sure this matches actual SearXNG output
	Author      *string `json:"author,omitempty"`
	Engine      string   `json:"engine,omitempty"`
	Engines     []string `json:"engines,omitempty"`
	Positions   []int    `json:"positions,omitempty"`
	Score       *float64 `json:"score,omitempty"`
	Category    string   `json:"category,omitempty"`
	PrettyURL   string   `json:"pretty_url,omitempty"`
	ImgSrc      string   `json:"img_src,omitempty"`
	Thumbnail   string   `json:"thumbnail,omitempty"`
	Template    string   `json:"template,omitempty"`
}

// SearxngWebSearchOutput defines the structured output for the searxng_web_search tool.
// It will contain a list of search results.
type SearxngWebSearchOutput struct {
	Results []SearxngResult `json:"results"`
	// We might also want to include information about the query, number of results, current page, etc.
	Query          string `json:"query,omitempty"`
	NumberOfResults int    `json:"number_of_results,omitempty"`
	CurrentPage    *int   `json:"current_page,omitempty"`
	// Add other fields as necessary from SearXNG response, like answer, corrections, suggestions etc.
}

// WebURLReadOutput defines the structured output for the web_url_read tool.
type WebURLReadOutput struct {
	MarkdownContent string `json:"markdownContent"`
	URL             string `json:"url"`
	Title           string `json:"title,omitempty"`
}

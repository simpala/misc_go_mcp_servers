package main

// SearxngWebSearchInput defines the input parameters for the searxng_web_search tool.
type SearxngWebSearchInput struct {
	Query      string  `json:"query"`
	PageNo     *int    `json:"pageno,omitempty"`     // Optional: Search page number, starts at 1 (default 1)
	TimeRange  *string `json:"time_range,omitempty"` // Optional: Filter results by time range - one of: "day", "month", "year" (default: none)
	Language   *string `json:"language,omitempty"`   // Optional: Language code for results (e.g., "en", "fr", "de") or "all" (default: "all")
	SafeSearch *int    `json:"safesearch,omitempty"` // Optional: Safe search filter level (0: None, 1: Moderate, 2: Strict) (default: instance setting)
}

// SearxngCategorySearchInput defines the input parameters for the searxng_category_search tool.
type SearxngCategorySearchInput struct {
	Query      string  `json:"query"`                // Mandatory: The search term or phrase.
	Category   string  `json:"category"`             // Mandatory: The category to search within (e.g., "images", "videos", "news").
	PageNo     *int    `json:"pageno,omitempty"`     // Optional: Search page number, starts at 1 (default 1).
	TimeRange  *string `json:"time_range,omitempty"` // Optional: Filter results by time range - one of: "day", "month", "year" (default: none).
	Language   *string `json:"language,omitempty"`   // Optional: Language code for results (e.g., "en", "fr", "de") or "all" (default: "all").
	SafeSearch *int    `json:"safesearch,omitempty"` // Optional: Safe search filter level (0: None, 1: Moderate, 2: Strict) (default: instance setting).
}

// WebURLReadInput defines the input parameters for the web_url_read tool.
type WebURLReadInput struct {
	URL string `json:"url"`
}

// SearxngResult defines the structure for a single search result from SearXNG.
// This is a simplified version based on common SearXNG output.
// We might need to adjust this based on the actual JSON structure from a SearXNG instance.
type SearxngResult struct {
	URL           string   `json:"url"`
	Title         string   `json:"title"`
	Content       string   `json:"content,omitempty"`
	PublishedDate *string  `json:"publishedDate,omitempty"` // Make sure this matches actual SearXNG output
	Author        *string  `json:"author,omitempty"`
	Engine        string   `json:"engine,omitempty"`
	Engines       []string `json:"engines,omitempty"`
	Positions     []int    `json:"positions,omitempty"`
	Score         *float64 `json:"score,omitempty"`
	Category      string   `json:"category,omitempty"` // This field in SearxngResult seems to be for the result's category, not the query's.
	PrettyURL     string   `json:"pretty_url,omitempty"`
	ImgSrc        string   `json:"img_src,omitempty"`
	Thumbnail     string   `json:"thumbnail,omitempty"`
	Template      string   `json:"template,omitempty"`
}

// SearxngWebSearchOutput defines the structured output for the searxng_web_search tool.
type SearxngWebSearchOutput struct {
	Results         []SearxngResult `json:"results"`
	Query           string          `json:"query,omitempty"`
	NumberOfResults int             `json:"number_of_results,omitempty"`
	CurrentPage     *int            `json:"current_page,omitempty"`
}

// SearxngCategorySearchOutput defines the structured output for the searxng_category_search tool.
type SearxngCategorySearchOutput struct {
	Results         []SearxngResult `json:"results"`
	Query           string          `json:"query,omitempty"`
	Category        string          `json:"category,omitempty"` // To echo back the category that was searched.
	NumberOfResults int             `json:"number_of_results,omitempty"`
	CurrentPage     *int            `json:"current_page,omitempty"`
}

// WebURLReadOutput defines the structured output for the web_url_read tool.
type WebURLReadOutput struct {
	MarkdownContent string `json:"markdownContent"`
	URL             string `json:"url"`
	Title           string `json:"title,omitempty"`
}

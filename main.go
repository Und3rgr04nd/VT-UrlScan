package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/valyala/fasthttp"
)

const API_KEY = "952ab59ba4ebc3bdc4a5d44fe5a90e5cdeb0079cd275f5ea3f12debdf0457fd8"

func getURLID(urlStr string) (map[string]interface{}, error) {
	endpoint := "https://www.virustotal.com/api/v3/urls"
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(endpoint)
	req.Header.SetMethod("POST")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Apikey", API_KEY)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBodyString(fmt.Sprintf("url=%s", urlStr))

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := fasthttp.Do(req, resp); err != nil {
		return nil, fmt.Errorf("error fetching URL ID: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %v", err)
	}

	return result, nil
}

func fetchScanResult(id string) (map[string]interface{}, error) {
	baseURL := fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", id)
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(baseURL)
	req.Header.SetMethod("GET")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Apikey", API_KEY)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := fasthttp.Do(req, resp); err != nil {
		return nil, fmt.Errorf("error fetching scan result: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %v", err)
	}

	return result, nil
}

func printScanResult(scanResult map[string]interface{}) {
	if scanResult == nil {
		fmt.Println("Failed to fetch scan result.")
		return
	}

	data, ok := scanResult["data"].(map[string]interface{})
	if !ok {
		fmt.Println("No data found in scan result.")
		return
	}

	analysisID := data["id"]
	attributes, _ := data["attributes"].(map[string]interface{})
	status := attributes["status"]
	date := attributes["date"]
	stats, _ := attributes["stats"].(map[string]interface{})
	results, _ := attributes["results"].(map[string]interface{})

	fmt.Printf("Analysis ID: %v\n", analysisID)
	fmt.Printf("Status: %v\n", status)
	fmt.Printf("Date: %v\n", date)

	fmt.Println("\nResults:")
	for engine, result := range results {
		resultMap, _ := result.(map[string]interface{})
		engineName := resultMap["engine_name"]
		category := resultMap["category"]
		resultStr := resultMap["result"]
		fmt.Printf("- %s: %v, %v, %v\n", engine, engineName, category, resultStr)
	}

	fmt.Println("\nStatistics:")
	fmt.Printf("- Malicious: %v\n", stats["malicious"])
	fmt.Printf("- Suspicious: %v\n", stats["suspicious"])
	fmt.Printf("- Undetected: %v\n", stats["undetected"])
	fmt.Printf("- Harmless: %v\n", stats["harmless"])
	fmt.Printf("- Timeout: %v\n", stats["timeout"])

	categories, _ := attributes["categories"].([]interface{})
	if len(categories) > 0 {
		fmt.Println("\nCategories:")
		for _, category := range categories {
			fmt.Printf("- %v\n", category)
		}
	}

	history, _ := attributes["history"].(map[string]interface{})
	if len(history) > 0 {
		fmt.Println("\nHistory:")
		for key, value := range history {
			fmt.Printf("%s: %v\n", key, value)
		}
	}

	httpResponse, _ := attributes["http_response"].(map[string]interface{})
	if len(httpResponse) > 0 {
		fmt.Println("\nHTTP Response:")
		fmt.Printf("Final URL: %v\n", httpResponse["final_url"])
		fmt.Printf("Serving IP Address: %v\n", httpResponse["serving_ip_address"])
		fmt.Printf("Status Code: %v\n", httpResponse["status_code"])
		fmt.Printf("Body Length: %v bytes\n", httpResponse["body_length"])
		fmt.Printf("Body SHA-256: %v\n", httpResponse["body_sha256"])

		headers, _ := httpResponse["headers"].(map[string]interface{})
		if len(headers) > 0 {
			fmt.Println("\nHeaders:")
			for key, value := range headers {
				fmt.Printf("%s: %v\n", key, value)
			}
		}
	}

	htmlInfo, _ := attributes["html_info"].(map[string]interface{})
	if len(htmlInfo) > 0 {
		fmt.Println("\nHTML Info:")
		fmt.Printf("Title: %v\n", htmlInfo["title"])
		fmt.Printf("Meta Tags: %v\n", htmlInfo["meta_tags"])
		fmt.Printf("Redirection chain: %v\n", htmlInfo["redirection_chain"])
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: main.go <Url>")
	}
	url := os.Args[1]

	getID, err := getURLID(url)
	if err != nil {
		fmt.Printf("Failed to fetch URL ID: %v\n", err)
		return
	}

	data, ok := getID["data"].(map[string]interface{})
	if !ok {
		fmt.Println("Failed to fetch URL ID.")
		return
	}

	urlID, ok := data["id"].(string)
	if !ok {
		fmt.Println("Failed to fetch URL ID.")
		return
	}

	scanResult, err := fetchScanResult(urlID)
	if err != nil {
		fmt.Printf("Failed to fetch scan result: %v\n", err)
		return
	}

	fmt.Println("\nScan Result:")
	printScanResult(scanResult)
}

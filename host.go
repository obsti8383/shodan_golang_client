package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

type HostLocation struct {
	City         string  `json:"city"`
	RegionCode   string  `json:"region_code"`
	AreaCode     int     `json:"area_code"`
	Longitude    float32 `json:"longitude"`
	CountryCode3 string  `json:"country_code3"`
	CountryName  string  `json:"country_name"`
	PostalCode   string  `json:"postal_code"`
	DMACode      int     `json:"dma_code"`
	CountryCode  string  `json:"country_code"`
	Latitude     float32 `json:"latitude"`
}

type Vulnerability struct {
	Verified   bool        `json:"verified"`
	References []string    `json:"references"`
	Cvss       interface{} `json:"cvss"` // sometimes float, sometimest string...
	Summary    string      `json:"summary"`
}

type Host struct {
	OS        string                   `json:"os"`
	Timestamp string                   `json:"timestamp"`
	ISP       string                   `json:"isp"`
	ASN       string                   `json:"asn"`
	Hostnames []string                 `json:"hostnames"`
	Location  HostLocation             `json:"location"`
	IP        int64                    `json:"ip"`
	Domains   []string                 `json:"domains"`
	Org       string                   `json:"org"`
	Data      string                   `json:"data"`
	Port      int                      `json:"port"`
	IPString  string                   `json:"ip_str"`
	Product   string                   `json:"product`
	Vulns     map[string]Vulnerability `json:"vulns"`
}

type ErrorResponse struct {
	Error      string `json:"error"`
	StatusCode int
}

type HostSearch struct {
	Matches []Host `json:"matches"`
}

func (s *Client) HostSearch(q string, maxPages int) (*HostSearch, error) {
	uri := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s", BaseURL, s.apiKey, url.QueryEscape(q))
	matches := make([]Host, 0, 100)

	fetchNextPage := true
	for i := 1; fetchNextPage && i <= maxPages; i++ {
		nextUri := uri
		if i > 1 {
			nextUri += fmt.Sprintf("&page=%d", i)
		}

		ret, err := s.hostSearchIterator(nextUri)
		if err != nil {
			return nil, err
		}
		matches = append(matches, ret.Matches...)

		if len(ret.Matches) < 100 {
			fetchNextPage = false
		}
	}

	var searchResult HostSearch
	searchResult.Matches = matches
	return &searchResult, nil
}

func (s *Client) hostSearchIterator(uri string) (searchResult *HostSearch, err error) {
	jsonByteArray, err := getJSONfromWebservice(uri, nil)
	if err != nil {
		// error handling
		// example error body response: {"error": "Please upgrade your API plan to use filters or paging."}
		var errorResp ErrorResponse
		if errUnmarshal := json.Unmarshal(jsonByteArray, &errorResp); errUnmarshal != nil {
			return nil, err
		}

		err = errors.New(errorResp.Error)
		return nil, err
	}

	//_ = ioutil.WriteFile("response.json", jsonByteArray, 0644)

	// evaluate JSON response
	var ret HostSearch
	if err := json.Unmarshal(jsonByteArray, &ret); err != nil {
		return nil, err
	}

	return &ret, nil
}

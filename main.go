// shodan command line tool
// source code partly from github.com/blackhat-go/bhg/ch-3/shodan/
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("Usage: main <searchterm>")
	}
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		log.Panicln("No API key set. Please set env variable SHODAN_API_KEY.")
	}
	s := New(apiKey)
	info, err := s.APIInfo()
	if err != nil {
		log.Panicln(err)
	}
	fmt.Printf(
		"Query Credits: %d\nScan Credits:  %d\n\n",
		info.QueryCredits,
		info.ScanCredits)

	hostSearch, nextlink, err := s.HostSearch(os.Args[1])
	fmt.Println(nextlink)
	if err != nil {
		fmt.Println("ERROR:", err.Error())
		return
	}

	for _, host := range hostSearch.Matches {
		//fmt.Printf("%18s:%d\t%s\t%s\t%s\t%s\t%s\n", host.IPString, host.Port, host.Hostnames, host.Org, host.Location.City, host.OS, host.Timestamp)
		// hostnames in single lines only:
		for _, hostname := range host.Hostnames {
			fmt.Printf("%s\n", hostname)
		}
	}
	fmt.Println("Number of results:", len(hostSearch.Matches))

	//for _, host := range hostSearch.Matches {
	//		fmt.Println(host.IPString, host.i)
	//}
}

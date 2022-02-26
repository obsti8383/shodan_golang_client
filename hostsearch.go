package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func HostSearchCommand(arguments []string, configuration Configuration, log *log.Logger, debugLog *log.Logger) int {
	var help bool
	var verbose bool
	var pages int
	flags := flag.NewFlagSet("host", flag.ContinueOnError)
	flags.BoolVar(&help, "help", help, "Show this help message")
	flags.BoolVar(&help, "h", help, "")
	flags.BoolVar(&verbose, "v", verbose, "Show verbose logging.")
	flags.IntVar(&pages, "pages", pages, "Maximum number of pages to fetch (100 entries per page)")
	err := flags.Parse(arguments)
	switch err {
	case flag.ErrHelp:
		help = true
	case nil:
	default:
		log.Fatalf("error parsing flags: %v", err)
	}
	// If the help flag was set, just show the help message and exit.
	if help {
		printHostHelp(flags)
		os.Exit(0)
	}
	// verbose output?
	if verbose || configuration.VerboseOutput {
		debugLog.SetOutput(os.Stderr)
	}
	// maxPages overwrite
	if pages != 0 {
		configuration.MaxPages = pages
	}

	args := flags.Args()
	fmt.Println(args)
	if len(args) < 1 {
		printHostHelp(flags)
		os.Exit(1)
	}
	searchString := args[0]

	s := New(configuration.Shodan_api_key)
	info, err := s.APIInfo()
	if err != nil {
		log.Print(err.Error())
		return 1
	}
	debugLog.Printf(
		"Query Credits: %d; Scan Credits:  %d",
		info.QueryCredits,
		info.ScanCredits)

	hostSearch, err := s.HostSearch(searchString, configuration.MaxPages)
	if err != nil {
		log.Print(err.Error())
		return 1
	}

	for _, host := range hostSearch.Matches {
		fmt.Printf("%s:%d\t%s\t%s\t%s\t%s\t%s\t%s\n", host.IPString, host.Port, host.Hostnames, host.Product, host.Org, host.Location.City, host.OS, host.Timestamp)
		for key, vuln := range host.Vulns {
			fmt.Printf("\tVulns: \t%s\t%v\n", key, vuln.Cvss)
		}
	}
	debugLog.Println("Number of results:", len(hostSearch.Matches))
	return 0
}

func printHostHelp(flags *flag.FlagSet) {
	fmt.Fprintf(flags.Output(), "Usage of command %s:\n", flags.Name())
	flags.PrintDefaults()
}

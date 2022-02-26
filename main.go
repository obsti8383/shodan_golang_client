// shodan command line tool
// source code partly from github.com/blackhat-go/bhg/ch-3/shodan/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

type Configuration struct {
	VerboseOutput  bool   `json:"verbose"`
	Shodan_api_key string `json:"shodan_api_key"`
	MaxPages       int    `json:"max_pages"`
}

func main() {
	logger := log.New(os.Stderr, "", 0)
	debug := log.New(io.Discard, "", 0)

	// get configuration from config json
	var configuration Configuration
	configFile := "config.json"
	file, err := os.Open(configFile)
	if err != nil {
		logger.Fatal(err.Error())
		return
	}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&configuration)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// evaluate command line flags
	var help bool
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.BoolVar(&help, "help", help, "Show this help message")
	flags.BoolVar(&help, "h", help, "")
	if len(os.Args) < 3 {
		printHelp(flags)
		os.Exit(2)
	}
	err = flags.Parse(os.Args[1:])
	switch err {
	case flag.ErrHelp:
		help = true
	case nil:
	default:
		logger.Fatalf("error parsing flags: %v", err)
	}
	// If the help flag was set, just show the help message and exit.
	if help {
		printHelp(flags)
		os.Exit(0)
	}

	if configuration.Shodan_api_key == "" {
		log.Println("No API key set. Please set shodan_api_key in config json.")
		printHelp(flags)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "host":
		os.Exit(HostSearchCommand(os.Args[2:], configuration, logger, debug))
	}

	log.Println("invalid command or command missing")
	printHelp(flags)
	os.Exit(1)
}

func printHelp(flags *flag.FlagSet) {
	fmt.Fprintf(flags.Output(), "Usage of %s:\n", os.Args[0])
	flags.PrintDefaults()
	fmt.Printf(`
Always enter a command and an search string as parameter, e.g.:
	host product:nginx

Possible commands are:
	host

To configure the command, at least the shodan_api_key must be set in config.json. Example:

	{
		"verbose": false,
		"shodan_api_key": "asicj738z8fhse7h28783hiuh",
		"max_pages": 3
	}
`)
}

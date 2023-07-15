package main

import (
	"bufio"
	"fmt"
	"github.com/BishopFox/jsluice"
	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/spf13/pflag"
	"io"
	"irotem.com/bounty-js-extract/downloader"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

type Source struct {
	BaseUrl string
	Url     string
	Scanned bool
	Exists  bool
	Type    string
	Secrets []string
}

func (s Source) String() string {
	return fmt.Sprintf(" %s Type: %s Exists: %t", s.Url, s.Type, s.Exists)
}

func main() {

	inputFile := pflag.String("input", "", "Input file path")
	scopes := pflag.StringSlice("scope", []string{"google"}, "Scope to search for")
	pflag.Parse()

	var reader io.Reader

	var lines []string

	if *inputFile != "" {
		file, err := os.Open(*inputFile)
		if err != nil {
			fmt.Println("Error opening file:", err)
			os.Exit(1)
		}
		defer file.Close()
		reader = file
	} else {
		reader = os.Stdin
	}

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading input:", err)
		os.Exit(1)
	}

	//var sources []string
	sources := make(map[string]*Source)
	mu := sync.Mutex{}
	err := downloader.DownloadList(lines, func(result runner.Result) {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)
		if result.StatusCode != 200 {
			return
		}

		response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(result.Raw)), nil)
		if err != nil {
			return
		}

		doc, err := goquery.NewDocumentFromReader(response.Body)
		if err != nil {
			return
		}

		doc.Find("script").Each(func(i int, s *goquery.Selection) {
			src, _ := s.Attr("src")
			dsrc, _ := s.Attr("data-src")
			if src != "" {
				mu.Lock()
				src = makeAbsolute(result.URL, src)
				sources[src] = &Source{
					BaseUrl: result.URL,
					Url:     src,
					Scanned: false,
					Exists:  false,
					Type:    "script",
				}

				mu.Unlock()
			}
			if dsrc != "" {
				mu.Lock()
				dsrc = makeAbsolute(result.URL, dsrc)
				sources[src] = &Source{
					BaseUrl: result.URL,
					Url:     src,
					Scanned: false,
					Exists:  false,
					Type:    "script",
				}
				mu.Unlock()
			}
		})
	})

	if err != nil {
		fmt.Println("Error downloading list:", err)
		return
	}

	for i := 0; i < 100; i++ {

		var sourcesList []string
		for k, source := range sources {
			if !source.Scanned {
				sourcesList = append(sourcesList, source.Url)
			}
			sources[k].Scanned = true
		}

		if len(sourcesList) == 0 {
			break
		}

		fmt.Println("Going to scan", len(sourcesList), "new sources")
		for _, s := range sourcesList {
			fmt.Println(s)
		}

		err = downloader.DownloadList(sourcesList, func(result runner.Result) {
			if result.StatusCode != 200 {
				return
			}

			src := sources[result.Input]
			src.Exists = true
			response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(result.Raw)), nil)
			if err != nil {
				return
			}

			// Read body bytes
			data, err := io.ReadAll(response.Body)

			if src.Type == "script" {
				analyzer := jsluice.NewAnalyzer(data)

				secrets := analyzer.GetSecrets()
				for _, secret := range secrets {
					fmt.Println("Found secret", secret)
				}

				urls := analyzer.GetURLs()
				for _, url := range urls {
					if strings.HasPrefix(url.URL, "no use strict") {
						continue
					}

					baseUrl := src.BaseUrl
					absUrl := makeAbsolute(baseUrl, url.URL)

					for _, s := range *scopes {
						if strings.Contains(absUrl, s) {
							if _, ok := sources[absUrl]; !ok {

								typeFound := "url"
								if strings.HasSuffix(absUrl, ".js") {
									typeFound = "script"
								}
								sources[absUrl] = &Source{
									BaseUrl: baseUrl,
									Url:     absUrl,
									Scanned: false,
									Type:    typeFound,
								}
							}
							break
						}
					}
				}
			}
		})
	}

	for _, source := range sources {
		fmt.Println(source)
	}
}

func makeAbsolute(myurl string, src string) string {
	u, err := url.Parse(myurl)
	if err != nil {
		return myurl
	}

	if strings.HasPrefix(src, "//") {
		return u.Scheme + ":" + src
	} else if strings.HasPrefix(src, "./") {
		return u.Scheme + "://" + u.Host + src[1:]
	} else if strings.HasPrefix(src, "/") && string(src[1]) != "/" {
		return u.Scheme + "://" + u.Host + src
	} else if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		return u.Scheme + "://" + u.Host + u.Path + "/" + src
	}
	return src

}

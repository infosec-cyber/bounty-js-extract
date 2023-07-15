package downloader

import (
	"github.com/projectdiscovery/httpx/common/customheader"
	"github.com/projectdiscovery/httpx/runner"
	"log"
	"os"
)

func DownloadList(listDownload []string, callback func(result runner.Result)) error {
	tmpfile, err := os.CreateTemp("", "tmpInput")
	if err != nil {
		return err
	}

	var headers customheader.CustomHeaders

	options := runner.Options{
		Methods:   "GET",
		Silent:    true,
		RateLimit: 20,
		Threads:   5,
		Retries:   3,
		//Debug:           true,
		//DebugRequests:   true,
		CustomHeaders:   headers,
		InputTargetHost: listDownload,
		//RequestURIs:     tmpfile.Name(),
		OnResult: callback,
	}

	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	httpxRunner.RunEnumeration()
	httpxRunner.Close()
	_ = os.RemoveAll(tmpfile.Name())

	return nil
}

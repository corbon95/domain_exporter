package whois

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caarlos0/domain_exporter/internal/client"
	"github.com/domainr/whois"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/idna"
)

const (
	ianaWhoisServer        = "whois.iana.org"
	ianaWhoisLookupTimeout = 3 * time.Second
)

// nolint: gochecknoglobals
var (
	formats = []string{
		time.ANSIC,
		time.UnixDate,
		time.RubyDate,
		time.RFC822,
		time.RFC822Z,
		time.RFC850,
		time.RFC1123,
		time.RFC1123Z,
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05-0700",    // some .com
		"20060102",                    // .com.br
		"20060102150405",              // .ua
		"2006-01-02",                  // .lt
		"2006-01-02 15:04:05-07",      // .ua
		"2006-01-02 15:04:05",         // .ch
		"2006-01-02T15:04:05Z",        // .name
		"2006-01-02T15:04:05.0Z",      // .host
		"January  2 2006",             // .is
		"02.01.2006",                  // .cz
		"02/01/2006",                  // .fr
		"02-January-2006",             // .ie
		"2006.01.02 15:04:05",         // .pl
		"02-Jan-2006",                 // .co.uk
		"02-Jan-2006 15:04:05",        // .sg
		"2006-01-02T15:04:05Z",        // .co
		"2006/01/02",                  // .ca, .jp
		"2006-01-02 (YYYY-MM-DD)",     // .tw
		"(dd/mm/yyyy): 02/01/2006",    // .pt
		"02-Jan-2006 15:04:05 UTC",    // .id, .co.id
		": 2006. 01. 02.",             // .kr
		"2006-01-02 15:04:05 (UTC+8)", // .tw
		"02/01/2006 15:04:05",         // .im
		"02.01.2006 15:04:05",         // .rs
		"02 Jan 2006",                 // .co.th
		"2.1.2006 15:04:05",           // .fi
		"02-01-2006",                  // .hk
		"2006-Jan-02.",                // .com.tr
		"2006-01-02 15:04:05 (GMT+0)", // .kz
		"2006-01-02T15:04:05Z",        // .ph
		"2006.01.02",                  // .ru
		"2006-01-02 15:04:05 CLST",    // .cl
		"2006-01-02 15:04:05 CLT",     // .cl
		"2006-01-02 15:04:05",         // .hk
	}

	// Match expiry fields only at the beginning of a WHOIS response line.
	// In particular, do not treat values such as "state: REGISTERED, ..." as dates.
	// nolint: lll
	expiryRE = regexp.MustCompile(`(?im)^[\t ]*\[?(` + strings.Join([]string{
		"Registrar Registration Expiration Date",
		"expire-date",
		"Valid Until",
		"Expire Date",
		"Registry Expiry Date",
		"paid-till",
		"Expiration Date",
		"Expiration Time",
		"Expiry date",
		"Expiry",
		"Expires on\\.{14}:",
		"Expires On",
		"expires\\.{12}",
		"expires",
		"Expires",
		"expire",
		"Renewal Date",
		"Record expires on",
		"Exp date",
		"Domain expired\\.*:",
		"OK-UNTIL",
	}, "|") + `)\]?:?[\t ]*(.*?)[\t\r ]*$`)
	registrarRE = regexp.MustCompile(`(?i)Registrar WHOIS Server: (.*)`)
	ianaWhoisRE = regexp.MustCompile(`(?im)^whois:[\t ]*([^\s]+)[\t\r ]*$`)
)

type whoisClient struct {
	ianaHosts sync.Map
}

// NewClient return a "live" whois client.
func NewClient() client.Client {
	return &whoisClient{}
}

func (c *whoisClient) ExpireTime(ctx context.Context, domain string, host string) (time.Time, error) {
	log.Debug().Msgf("trying whois client for %q", domain)

	if host != "" {
		return c.expireTime(ctx, domain, host)
	}

	// Prefer IANA's live TLD delegation data over the embedded zonedb metadata.
	// The latter can become stale when a registry changes its WHOIS endpoint.
	ianaHost, ianaErr := c.discoverWhoisHost(ctx, domain)
	if ianaErr == nil {
		if date, err := c.expireTime(ctx, domain, ianaHost); err == nil {
			return date, nil
		} else {
			ianaErr = fmt.Errorf("IANA-discovered WHOIS host %q failed: %w", ianaHost, err)
		}
	} else {
		ianaErr = fmt.Errorf("IANA WHOIS discovery failed: %w", ianaErr)
	}

	// Keep the old domainr/zonedb behavior as a compatibility fallback.
	date, legacyErr := c.expireTime(ctx, domain, "")
	if legacyErr == nil {
		return date, nil
	}

	return time.Time{}, fmt.Errorf("%v; zonedb fallback failed: %w", ianaErr, legacyErr)
}

func (c *whoisClient) expireTime(ctx context.Context, domain, host string) (time.Time, error) {
	body, err := c.request(ctx, domain, host)
	if err != nil {
		return time.Time{}, err
	}

	date, err := parseExpireTime(body)
	if err != nil {
		return time.Time{}, err
	}

	log.Debug().Msgf("domain %q will expire at %q", domain, date.String())
	return date, nil
}

func parseExpireTime(body string) (time.Time, error) {
	results := expiryRE.FindAllStringSubmatch(body, -1)
	if len(results) == 0 {
		return time.Time{}, fmt.Errorf("could not parse whois response: %q", body)
	}

	var lastDateStr string
	for _, result := range results {
		if len(result) < 3 {
			continue
		}
		dateStr := strings.TrimSpace(result[2])
		lastDateStr = dateStr
		for _, format := range formats {
			if date, err := time.Parse(format, dateStr); err == nil {
				return date, nil
			}
		}
	}

	return time.Time{}, fmt.Errorf("could not parse date: %q", lastDateStr)
}

func (c *whoisClient) discoverWhoisHost(ctx context.Context, domain string) (string, error) {
	tld, err := tldFromDomain(domain)
	if err != nil {
		return "", err
	}

	if cached, ok := c.ianaHosts.Load(tld); ok {
		return cached.(string), nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, ianaWhoisLookupTimeout)
	defer cancel()

	req := &whois.Request{
		Query: tld,
		Host:  ianaWhoisServer,
	}
	if err := req.Prepare(); err != nil {
		return "", fmt.Errorf("failed to prepare IANA WHOIS request: %w", err)
	}

	resp, err := whois.DefaultClient.FetchContext(lookupCtx, req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch IANA WHOIS request: %w", err)
	}
	respText, err := resp.Text()
	if err != nil {
		return "", fmt.Errorf("failed to parse IANA WHOIS response: %w", err)
	}

	host, err := parseIANAWhoisHost(string(respText))
	if err != nil {
		return "", err
	}
	c.ianaHosts.Store(tld, host)
	log.Debug().Msgf("IANA reports WHOIS host %s for .%s", host, tld)
	return host, nil
}

func parseIANAWhoisHost(body string) (string, error) {
	result := ianaWhoisRE.FindStringSubmatch(body)
	if len(result) < 2 {
		return "", fmt.Errorf("could not find WHOIS server in IANA response")
	}

	host := strings.TrimSpace(result[1])
	if host == "" {
		return "", fmt.Errorf("IANA returned an empty WHOIS server")
	}
	return host, nil
}

func tldFromDomain(domain string) (string, error) {
	normalizedDomain, err := normalizeDomain(domain)
	if err != nil {
		return "", err
	}

	idx := strings.LastIndexByte(normalizedDomain, '.')
	if idx < 0 || idx == len(normalizedDomain)-1 {
		return "", fmt.Errorf("could not determine TLD for domain %q", domain)
	}
	return normalizedDomain[idx+1:], nil
}

func normalizeDomain(domain string) (string, error) {
	normalizedDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if normalizedDomain == "" {
		return "", fmt.Errorf("domain name is empty")
	}

	normalizedDomain, err := idna.ToASCII(normalizedDomain)
	if err != nil {
		return "", fmt.Errorf("failed to normalize domain name: %w", err)
	}
	return normalizedDomain, nil
}

func (c *whoisClient) request(ctx context.Context, domain, host string) (string, error) {
	normalizedDomain, err := normalizeDomain(domain)
	if err != nil {
		return "", err
	}

	req := &whois.Request{
		Query: normalizedDomain,
		Host:  host,
	}
	if err := req.Prepare(); err != nil {
		return "", fmt.Errorf("failed to prepare: %w", err)
	}
	resp, err := whois.DefaultClient.FetchContext(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch whois request: %w", err)
	}
	respText, err := resp.Text()
	if err != nil {
		return "", fmt.Errorf("failed to parse response body into text: %w", err)
	}

	body := string(respText)

	if host == "" {
		// do not recurse
		return body, nil
	}

	result := registrarRE.FindStringSubmatch(body)
	if len(result) < 2 {
		log.Debug().Msgf("couldn't find registrar url in whois response: %s", domain)
		return body, nil
	}

	foundHost := strings.TrimSpace(result[1])
	if foundHost == host || foundHost == "" {
		return body, nil
	}

	log.Debug().Msgf("found whois host %s for domain %s", foundHost, domain)
	if newBody, err := c.request(ctx, domain, foundHost); err == nil {
		return newBody, nil
	}

	log.Debug().Msgf("ignoring error from %s for %s", foundHost, domain)
	return body, nil
}

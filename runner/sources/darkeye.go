package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vflame6/leaker/logger"
	"github.com/vflame6/leaker/utils"
)

// DarkEye queries the two public DarkEye APIs in a single source:
//
//   - Have I Been Ransomed? (haveibeenransom.com): ransomware leak-site posts and
//     data breaches for a domain.
//   - Breach House (breach.house): ransomware victims, data breaches, leads and
//     stealer records matching a domain.
//
// Each product has its own API key. Either one is enough. Only listing metadata
// is returned (title, website, group, country, date); leaked records, proof
// files and leak-site or download URLs are never read from the responses.
//
// Keys are configured with a product prefix, one list entry per key:
//
//	darkeye: ["hibr:YOUR_HIBR_KEY", "breachhouse:YOUR_BREACH_HOUSE_KEY"]
type DarkEye struct {
	hibrKeys []string
	bhKeys   []string

	// hibrBaseURL and breachHouseBaseURL override the API roots (tests only).
	hibrBaseURL        string
	breachHouseBaseURL string
	// noDelay disables the pause between requests (tests only).
	noDelay bool
	// maxPages overrides darkEyeHIBRMaxPages when set (tests only).
	maxPages int
}

const (
	darkEyeHIBRBaseURL        = "https://haveibeenransom.com"
	darkEyeBreachHouseBaseURL = "https://breach.house/api/v1"

	darkEyeHIBRName        = "Have I Been Ransomed?"
	darkEyeBreachHouseName = "Breach House"

	darkEyeHIBRPrefix        = "hibr"
	darkEyeBreachHousePrefix = "breachhouse"

	// Every HIBR page counts as one request against the key's quota, so the
	// number of pages fetched per lookup is capped.
	darkEyeHIBRMaxPages = 5
	// Max results per category for one Breach House search (the API maximum is 200).
	darkEyeBreachHouseLimit = 25

	// Upper bound for a response body, as a guard against unexpected payloads.
	darkEyeMaxBodySize = 8 << 20
	// Upper bound for a single metadata value.
	darkEyeMaxFieldRunes = 200
)

// Breach House returns one list per category in this order.
var darkEyeBreachHouseCategories = []string{"ransomware", "breaches", "leads", "stealers"}

// darkEyeHIBRCategories maps the HIBR leak_type values to the category names.
var darkEyeHIBRCategories = map[string]string{
	"ransomware_leak":    "ransomware",
	"traditional_breach": "breaches",
}

// The APIs treat * and ? as wildcards, so only plain domain names are queried.
var darkEyeDomainRegex = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// darkEyeText is a metadata value that may arrive as a JSON string or number.
// Any other JSON type decodes to an empty value instead of failing the response.
type darkEyeText string

func (t *darkEyeText) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch val := v.(type) {
	case string:
		*t = darkEyeText(val)
	case float64:
		*t = darkEyeText(strconv.FormatFloat(val, 'f', -1, 64))
	default:
		*t = ""
	}
	return nil
}

// darkEyeItem holds the only fields read from a HIBR or Breach House record.
type darkEyeItem struct {
	IDSource   darkEyeText `json:"id_source"`
	ID         darkEyeText `json:"id"`
	VictimID   darkEyeText `json:"victim_id"`
	LeakType   darkEyeText `json:"leak_type"`
	PostTitle  darkEyeText `json:"post_title"`
	Name       darkEyeText `json:"name"`
	Website    darkEyeText `json:"website"`
	GroupName  darkEyeText `json:"group_name"`
	Country    darkEyeText `json:"country"`
	Discovered darkEyeText `json:"discovered"`
}

type darkEyeHIBRPage struct {
	Sources    []json.RawMessage `json:"sources"`
	Results    []json.RawMessage `json:"results"`
	HasNext    *bool             `json:"has_next"`
	Pagination struct {
		HasNext bool `json:"has_next"`
	} `json:"pagination"`
}

// darkEyeRecord is a parsed record together with its product and category.
type darkEyeRecord struct {
	product  string
	category string
	id       string
	item     darkEyeItem
}

func (s *DarkEye) Run(ctx context.Context, target string, scanType ScanType, session *Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		// DarkEye is searched by domain only.
		if scanType != TypeDomain {
			return
		}

		hibrKey := utils.PickRandom(s.hibrKeys, s.Name(), s.NeedsKey())
		bhKey := utils.PickRandom(s.bhKeys, s.Name(), s.NeedsKey())
		if hibrKey == "" && bhKey == "" {
			return
		}

		domain, ok := normalizeDarkEyeDomain(target)
		if !ok {
			send(ctx, results, Result{Source: s.Name(), Error: fmt.Errorf("DarkEye needs a plain domain name, got %q", target)})
			return
		}

		// Each product is queried on its own: when one fails, the records of the
		// other one are still returned and the failure is reported as an error result.
		if hibrKey != "" {
			records, err := s.fetchHIBR(ctx, session, hibrKey, domain)
			if !s.emit(ctx, results, domain, records) {
				return
			}
			if err != nil && (ctx.Err() != nil || !send(ctx, results, Result{Source: s.Name(), Error: err})) {
				return
			}
		}

		if bhKey != "" {
			if hibrKey != "" && !s.pause(ctx) {
				return
			}
			records, err := s.fetchBreachHouse(ctx, session, bhKey, domain)
			if !s.emit(ctx, results, domain, records) {
				return
			}
			if err != nil && ctx.Err() == nil {
				send(ctx, results, Result{Source: s.Name(), Error: err})
			}
		}
	}()

	return results
}

// send delivers a result unless the context is cancelled first.
func send(ctx context.Context, results chan<- Result, r Result) bool {
	select {
	case results <- r:
		return true
	case <-ctx.Done():
		return false
	}
}

// emit converts the records to results and sends them.
func (s *DarkEye) emit(ctx context.Context, results chan<- Result, domain string, records []darkEyeRecord) bool {
	for _, record := range records {
		r, ok := s.recordToResult(record, domain)
		if !ok {
			continue
		}
		if !send(ctx, results, r) {
			return false
		}
	}
	return true
}

// pause waits between two requests to respect the rate limit.
func (s *DarkEye) pause(ctx context.Context) bool {
	if s.noDelay {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(time.Second / time.Duration(s.RateLimit())):
		return true
	}
}

// fetchHIBR reads up to darkEyeHIBRMaxPages pages of Have I Been Ransomed? records.
// Records read before a failure are returned together with the error.
func (s *DarkEye) fetchHIBR(ctx context.Context, session *Session, apiKey, domain string) ([]darkEyeRecord, error) {
	var records []darkEyeRecord
	seen := make(map[string]struct{})

	maxPages := darkEyeHIBRMaxPages
	if s.maxPages > 0 {
		maxPages = s.maxPages
	}

	for page := 1; page <= maxPages; page++ {
		if page > 1 && !s.pause(ctx) {
			return records, ctx.Err()
		}

		endpoint := s.hibrRoot() + "/api/metadata/domain/" + url.PathEscape(domain)
		if page > 1 {
			endpoint += "/" + strconv.Itoa(page)
		}

		body, err := s.get(ctx, session, darkEyeHIBRName, endpoint, apiKey)
		if err != nil {
			return records, err
		}

		var data darkEyeHIBRPage
		if err := json.Unmarshal(body, &data); err != nil {
			return records, fmt.Errorf("%s returned an invalid response", darkEyeHIBRName)
		}

		// The API returns "sources"; its documentation shows "results".
		raw := data.Sources
		if len(raw) == 0 {
			raw = data.Results
		}
		for _, entry := range raw {
			var item darkEyeItem
			if err := json.Unmarshal(entry, &item); err != nil {
				continue
			}
			// A leak indexed while paging is repeated on a later page.
			id := strings.TrimSpace(string(item.IDSource))
			if id == "" {
				id = strings.TrimSpace(string(item.ID))
			}
			if id != "" {
				if _, dup := seen[id]; dup {
					continue
				}
				seen[id] = struct{}{}
			}
			leakType := strings.TrimSpace(string(item.LeakType))
			category, known := darkEyeHIBRCategories[leakType]
			if !known {
				category = darkEyeClean(leakType)
			}
			records = append(records, darkEyeRecord{product: darkEyeHIBRName, category: category, id: id, item: item})
		}

		// A page can be short or even empty and still have a next page.
		hasNext := data.Pagination.HasNext
		if data.HasNext != nil {
			hasNext = *data.HasNext
		}
		if !hasNext {
			return records, nil
		}
		if page == maxPages {
			logger.Debugf("DarkEye reached the Have I Been Ransomed? page cap [%d] with more results available", maxPages)
		}
	}

	return records, nil
}

// fetchBreachHouse runs one cross-source search on Breach House.
func (s *DarkEye) fetchBreachHouse(ctx context.Context, session *Session, apiKey, domain string) ([]darkEyeRecord, error) {
	q := url.Values{}
	q.Set("q", domain)
	q.Set("limit", strconv.Itoa(darkEyeBreachHouseLimit))
	endpoint := s.breachHouseRoot() + "/search?" + q.Encode()

	body, err := s.get(ctx, session, darkEyeBreachHouseName, endpoint, apiKey)
	if err != nil {
		return nil, err
	}

	var data map[string]json.RawMessage
	if err := json.Unmarshal(body, &data); err != nil || data == nil {
		return nil, fmt.Errorf("%s returned an invalid response", darkEyeBreachHouseName)
	}

	var records []darkEyeRecord
	for _, category := range darkEyeBreachHouseCategories {
		entries := darkEyeBreachHouseEntries(data[category])
		if len(entries) >= darkEyeBreachHouseLimit {
			logger.Debugf("DarkEye reached the Breach House limit [%d] for %s", darkEyeBreachHouseLimit, category)
		}
		for _, entry := range entries {
			var item darkEyeItem
			if err := json.Unmarshal(entry, &item); err != nil {
				continue
			}
			id := strings.TrimSpace(string(item.VictimID))
			if id == "" {
				id = strings.TrimSpace(string(item.ID))
			}
			records = append(records, darkEyeRecord{product: darkEyeBreachHouseName, category: category, id: id, item: item})
		}
	}
	return records, nil
}

// darkEyeBreachHouseEntries returns the items of one Breach House category,
// which is either a plain list or an object with a "results" list.
func darkEyeBreachHouseEntries(raw json.RawMessage) []json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var wrapped struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		return wrapped.Results
	}
	return nil
}

// redact removes every configured API key from a message.
func (s *DarkEye) redact(msg string) string {
	for _, keys := range [][]string{s.hibrKeys, s.bhKeys} {
		for _, key := range keys {
			msg = strings.ReplaceAll(msg, key, "[redacted]")
		}
	}
	return msg
}

// get performs an authenticated GET request and returns the response body.
// Errors never include the API key or the response body.
func (s *DarkEye) get(ctx context.Context, session *Session, product, endpoint, apiKey string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s request could not be created", product)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	logger.Debugf("Sending a request in DarkEye source to %s", product)
	resp, err := session.Client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("%s request failed: %s", product, s.redact(err.Error()))
	}
	defer session.DiscardHTTPResponse(resp)

	body, err := io.ReadAll(io.LimitReader(resp.Body, darkEyeMaxBodySize))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("%s response could not be read", product)
	}
	logger.Debugf("Response from DarkEye source (%s): status code [%d], size [%d]", product, resp.StatusCode, len(body))

	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("%s authentication failed (status %d), check its API key", product, resp.StatusCode)
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("%s quota or rate limit reached (status %d), retry later", product, resp.StatusCode)
	default:
		return nil, fmt.Errorf("%s returned status %d", product, resp.StatusCode)
	}
}

// recordToResult maps a record to a Result that carries listing metadata only.
//
// Results that do not mention the searched domain are dropped by the default
// result filter. The HIBR endpoint is keyed by domain, so its records are tied to
// the domain even when the record has no website of its own: URL then holds the
// searched domain. Breach House runs a free-text search, so its records keep their
// own website and are filtered like any other result.
func (s *DarkEye) recordToResult(record darkEyeRecord, domain string) (Result, bool) {
	item := record.item

	website := darkEyeClean(string(item.Website))
	title := darkEyeClean(string(item.PostTitle))
	if title == "" {
		title = darkEyeClean(string(item.Name))
	}
	if title == "" {
		title = website
	}

	r := Result{
		Source:   s.Name(),
		Database: title,
		URL:      website,
	}
	if record.product == darkEyeHIBRName && !strings.Contains(strings.ToLower(website), domain) {
		r.URL = domain
		if website != "" {
			r.SetExtra("website", website)
		}
	}
	if r.Database == "" && r.URL == "" {
		return Result{}, false
	}

	r.SetExtra("product", record.product)
	if record.category != "" {
		r.SetExtra("category", record.category)
	}
	if v := darkEyeClean(string(item.GroupName)); v != "" {
		r.SetExtra("group", v)
	}
	if v := darkEyeClean(string(item.Country)); v != "" {
		r.SetExtra("country", v)
	}
	if v := darkEyeDate(string(item.Discovered)); v != "" {
		r.SetExtra("date", v)
	}
	// The listing id keeps two records of the same day and group apart in the
	// result deduplication, which ignores the Database field.
	if v := darkEyeClean(record.id); v != "" {
		r.SetExtra("record_id", v)
	}
	return r, true
}

// normalizeDarkEyeDomain returns the lowercase plain domain name for target.
// Wildcards, URLs, IP addresses and other garbage are rejected.
func normalizeDarkEyeDomain(target string) (string, bool) {
	domain := strings.TrimRight(strings.ToLower(strings.TrimSpace(target)), ".")
	if len(domain) > 253 || !darkEyeDomainRegex.MatchString(domain) {
		return "", false
	}
	// An IP address matches the pattern above; a TLD is never numeric.
	tld := domain[strings.LastIndex(domain, ".")+1:]
	if _, err := strconv.Atoi(tld); err == nil {
		return "", false
	}
	return domain, true
}

// darkEyeClean returns a single-line, printable, length-limited copy of a value.
// Titles come from third-party leak sites, so control characters (for example
// terminal escape sequences) are removed before they reach the output.
func darkEyeClean(value string) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if utf8.RuneCountInString(value) > darkEyeMaxFieldRunes {
		value = string([]rune(value)[:darkEyeMaxFieldRunes])
	}
	return value
}

// darkEyeDate keeps the YYYY-MM-DD part of a timestamp, or "" when it is not a date.
func darkEyeDate(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < len("2006-01-02") {
		return ""
	}
	day := value[:len("2006-01-02")]
	if _, err := time.Parse("2006-01-02", day); err != nil {
		return ""
	}
	return day
}

func (s *DarkEye) hibrRoot() string {
	if s.hibrBaseURL != "" {
		return strings.TrimRight(s.hibrBaseURL, "/")
	}
	return darkEyeHIBRBaseURL
}

func (s *DarkEye) breachHouseRoot() string {
	if s.breachHouseBaseURL != "" {
		return strings.TrimRight(s.breachHouseBaseURL, "/")
	}
	return darkEyeBreachHouseBaseURL
}

func (s *DarkEye) Name() string {
	return "darkeye"
}

func (s *DarkEye) UsesKey() bool {
	return true
}

func (s *DarkEye) NeedsKey() bool {
	return true
}

// AddApiKeys accepts keys prefixed with the product they belong to:
// "hibr:KEY" for Have I Been Ransomed? and "breachhouse:KEY" for Breach House.
// One of the two is enough.
func (s *DarkEye) AddApiKeys(keys []string) {
	for _, key := range keys {
		idx := strings.Index(key, ":")
		if idx < 0 {
			logger.Warnf("DarkEye: invalid key format, expected %s:API_KEY or %s:API_KEY", darkEyeHIBRPrefix, darkEyeBreachHousePrefix)
			continue
		}
		prefix := strings.ToLower(strings.TrimSpace(key[:idx]))
		value := strings.TrimSpace(key[idx+1:])
		if value == "" {
			logger.Warnf("DarkEye: empty key ignored")
			continue
		}
		switch prefix {
		case darkEyeHIBRPrefix:
			s.hibrKeys = append(s.hibrKeys, value)
		case darkEyeBreachHousePrefix:
			s.bhKeys = append(s.bhKeys, value)
		default:
			logger.Warnf("DarkEye: unknown key prefix, expected %s or %s", darkEyeHIBRPrefix, darkEyeBreachHousePrefix)
		}
	}
}

// RateLimit is a conservative default (one request per second), not a documented limit.
func (s *DarkEye) RateLimit() int {
	return 1
}

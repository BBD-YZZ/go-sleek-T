// Package fingerprint 提供主动指纹识别功能。
// 扫描前主动探测目标技术栈（WAF/CDN/框架/服务器），智能过滤无关模板。
package fingerprint

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/logutil"
	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/pkg/types"
)

const defaultTTL = 5 * time.Minute
const failTTL = 30 * time.Second

type cacheEntry struct {
	fp        *TargetFingerprint
	createdAt time.Time
}

// TargetFingerprint holds detected technology indicators for a target.
type TargetFingerprint struct {
	Target    string
	Titles    []string
	Headers   map[string]string
	Server    string
	Body      string
	TechStack map[string]bool // e.g. {"nginx": true, "php": true, "wordpress": true}

	// Additional tech indicators
	WAF       string // detected WAF name
	CDN       string // detected CDN name
	Framework string // detected web framework
	CMS       string // detected CMS
}

// Detector identifies target technology stack for pre-filtering templates.
type Detector struct {
	client *httpclient.Client
	cache  sync.Map // target → *cacheEntry
}

// New creates a fingerprint detector.
func New(client *httpclient.Client) *Detector {
	return &Detector{client: client}
}

// Detect probes a target to determine its technology stack.
func (d *Detector) Detect(ctx context.Context, target string) *TargetFingerprint {
	if raw, ok := d.cache.Load(target); ok {
		entry := raw.(*cacheEntry)
		if time.Since(entry.createdAt) < defaultTTL {
			return entry.fp
		}
		d.cache.Delete(target)
	}

	fp := &TargetFingerprint{
		Target:    target,
		Headers:   make(map[string]string),
		TechStack: make(map[string]bool),
	}

	// Probe main page
	if !d.probeTarget(ctx, fp, target) {
		d.cache.Store(target, &cacheEntry{fp: fp, createdAt: time.Now()})
		return fp
	}

	// Probe additional endpoints for more signals
	d.probeRobotsTxt(ctx, fp, target)
	d.probeFavicon(ctx, fp, target)

	d.cache.Store(target, &cacheEntry{fp: fp, createdAt: time.Now()})
	return fp
}

// probeTarget sends a GET request to the target and extracts fingerprints.
func (d *Detector) probeTarget(ctx context.Context, fp *TargetFingerprint, target string) bool {
	ti := placeholder.ParseTarget(target)
	rawReq := placeholder.New(ti, nil).ReplaceWithEscape(
		"GET / HTTP/1.1\r\nHost: {{Hostname}}\r\nUser-Agent: gosleek-fp/1.0\r\nConnection: close\r\n\r\n",
	)

	resp, err := d.client.SendRaw(ctx, target, rawReq)
	if err != nil {
		logutil.Log("warn", "指纹", "探测失败: %s err=%v", target, err)
		return false
	}

	fp.Body = resp.Body

	// Extract headers
	for k, vs := range resp.Headers {
		if len(vs) > 0 {
			fp.Headers[k] = vs[0]
		}
	}
	if server := resp.GetHeader("Server"); server != "" {
		fp.Server = server
	}

	// Extract title
	fp.Titles = extractTitles(resp.Body)

	// Detect technologies
	d.detectTech(fp)
	d.detectWAF(fp)
	d.detectCDN(fp)
	d.detectCMS(fp)

	if len(fp.TechStack) > 0 || fp.WAF != "" || fp.CDN != "" || fp.CMS != "" {
		logutil.Log("信息", "指纹", "目标 %s: tech=%v waf=%s cdn=%s cms=%s",
			target, fp.TechStack, fp.WAF, fp.CDN, fp.CMS)
	}

	return true
}

// probeRobotsTxt probes /robots.txt for additional signals.
func (d *Detector) probeRobotsTxt(ctx context.Context, fp *TargetFingerprint, target string) {
	req := "GET /robots.txt HTTP/1.1\r\nHost: {{Hostname}}\r\nUser-Agent: gosleek-fp/1.0\r\nConnection: close\r\n\r\n"
	ti := placeholder.ParseTarget(target)
	rawReq := placeholder.New(ti, nil).ReplaceWithEscape(req)
	resp, err := d.client.SendRaw(ctx, target, rawReq)
	if err != nil {
		return
	}
	if resp.StatusCode == 200 && resp.Body != "" {
		body := strings.ToLower(resp.Body)
		if strings.Contains(body, "wordpress") || strings.Contains(body, "wp-") {
			fp.TechStack["wordpress"] = true
			fp.CMS = "WordPress"
		}
		if strings.Contains(body, "joomla") {
			fp.TechStack["joomla"] = true
			fp.CMS = "Joomla"
		}
		if strings.Contains(body, "drupal") {
			fp.TechStack["drupal"] = true
			fp.CMS = "Drupal"
		}
	}
}

// probeFavicon probes /favicon.ico for additional signals.
func (d *Detector) probeFavicon(ctx context.Context, fp *TargetFingerprint, target string) {
	req := "GET /favicon.ico HTTP/1.1\r\nHost: {{Hostname}}\r\nUser-Agent: gosleek-fp/1.0\r\nConnection: close\r\n\r\n"
	ti := placeholder.ParseTarget(target)
	rawReq := placeholder.New(ti, nil).ReplaceWithEscape(req)
	resp, err := d.client.SendRaw(ctx, target, rawReq)
	if err != nil {
		return
	}
	// Check response headers and body for favicon
	if resp != nil {
		// Collect additional headers (not just specific ones)
		for k, v := range resp.Headers {
			if len(v) > 0 && fp.Headers[k] == "" {
				fp.Headers[k] = v[0]
			}
		}
		// Check body for Spring Boot 404 from favicon path
		if strings.Contains(strings.ToLower(resp.Body), "spring") {
			fp.TechStack["spring"] = true
			if fp.Framework == "" {
				fp.Framework = "Spring Boot"
			}
		}
	}
}

// detectTech extracts technology information from headers and body.
func (d *Detector) detectTech(fp *TargetFingerprint) {
	server := strings.ToLower(fp.Server)
	body := strings.ToLower(fp.Body)

	// Server identification
	if strings.Contains(server, "nginx") {
		fp.TechStack["nginx"] = true
	}
	if strings.Contains(server, "apache") {
		fp.TechStack["apache"] = true
	}
	if strings.Contains(server, "iis") || strings.Contains(server, "mswin") {
		fp.TechStack["iis"] = true
	}
	if strings.Contains(server, "tomcat") {
		fp.TechStack["tomcat"] = true
	}

	// Title-based detection
	for _, title := range fp.Titles {
		t := strings.ToLower(title)
		if strings.Contains(t, "wordpress") {
			fp.TechStack["wordpress"] = true
			if fp.CMS == "" {
				fp.CMS = "WordPress"
			}
		}
		if strings.Contains(t, "joomla") {
			fp.TechStack["joomla"] = true
			if fp.CMS == "" {
				fp.CMS = "Joomla"
			}
		}
		if strings.Contains(t, "drupal") {
			fp.TechStack["drupal"] = true
			if fp.CMS == "" {
				fp.CMS = "Drupal"
			}
		}
	}

	// Header-based detection
	for k, v := range fp.Headers {
		lk := strings.ToLower(k)
		lv := strings.ToLower(v)

		switch lk {
		case "x-powered-by":
			if strings.Contains(lv, "php") {
				fp.TechStack["php"] = true
			}
			if strings.Contains(lv, "asp") || strings.Contains(lv, "net") {
				fp.TechStack["asp"] = true
			}
			if strings.Contains(lv, "express") {
				fp.TechStack["express"] = true
				fp.Framework = "Express.js"
			}
			if strings.Contains(lv, "django") || strings.Contains(lv, "flask") {
				fp.TechStack["python"] = true
				fp.Framework = "Django/Flask"
			}
			if strings.Contains(lv, "laravel") {
				fp.TechStack["laravel"] = true
				fp.Framework = "Laravel"
			}
		case "set-cookie":
			if strings.Contains(lv, "phpsessid") {
				fp.TechStack["php"] = true
			}
			if strings.Contains(lv, "jsessionid") {
				fp.TechStack["java"] = true
			}
			if strings.Contains(lv, "asp.net") || strings.Contains(lv, "aspsessionid") {
				fp.TechStack["asp"] = true
			}
		case "server":
			// Already handled above
		}
	}

	// Body-based detection
	if strings.Contains(body, "wp-content") || strings.Contains(body, "wp-includes") {
		fp.TechStack["wordpress"] = true
		if fp.CMS == "" {
			fp.CMS = "WordPress"
		}
	}
	if strings.Contains(body, "<?php") || strings.Contains(body, "phpversion()") {
		fp.TechStack["php"] = true
	}
	if strings.Contains(body, "django") || strings.Contains(body, "csrfmiddlewaretoken") {
		fp.TechStack["django"] = true
		if fp.Framework == "" {
			fp.Framework = "Django"
		}
	}
	if strings.Contains(body, "rails") || strings.Contains(body, "data-turbo") {
		fp.TechStack["rails"] = true
		if fp.Framework == "" {
			fp.Framework = "Ruby on Rails"
		}
	}
	if strings.Contains(body, "spring") || strings.Contains(body, "spring-boot") {
		fp.TechStack["spring"] = true
		if fp.Framework == "" {
			fp.Framework = "Spring Boot"
		}
	}
	// Spring Boot 默认 404 JSON 响应
	if strings.Contains(body, "\"timestamp\"") && strings.Contains(body, "\"path\"") &&
		strings.Contains(body, "\"status\"") && strings.Contains(body, "\"error\"") {
		fp.TechStack["spring"] = true
		if fp.Framework == "" {
			fp.Framework = "Spring Boot"
		}
	}
}

// detectWAF extracts WAF information from response headers.
func (d *Detector) detectWAF(fp *TargetFingerprint) {
	for k, v := range fp.Headers {
		lk := strings.ToLower(k)
		lv := strings.ToLower(string(v[0]))

		switch {
		case strings.Contains(lv, "cloudflare") || strings.Contains(lk, "cf-"):
			fp.WAF = "Cloudflare"
		case strings.Contains(lv, "akamai") || strings.Contains(lk, "x-amz-"):
			fp.WAF = "Akamai"
		case strings.Contains(lv, "aws-waf") || strings.Contains(lk, "aws"):
			fp.WAF = "AWS WAF"
		case strings.Contains(lv, "f5") || strings.Contains(lk, "x-varnish"):
			fp.WAF = "F5"
		case strings.Contains(lv, "imperva") || strings.Contains(lk, "x-sucuri"):
			fp.WAF = "Imperva/Sucuri"
		case strings.Contains(lv, "cloudfront"):
			fp.WAF = "AWS CloudFront"
		case strings.Contains(lv, "barracuda"):
			fp.WAF = "Barracuda"
		case strings.Contains(lv, "dotdefender"):
			fp.WAF = "DotDefender"
		case strings.Contains(lv, "mod-security"):
			fp.WAF = "ModSecurity"
		}
	}
}

// detectCDN extracts CDN information from response headers.
func (d *Detector) detectCDN(fp *TargetFingerprint) {
	for k, v := range fp.Headers {
		lk := strings.ToLower(k)
		lv := strings.ToLower(string(v[0]))

		switch {
		case strings.Contains(lv, "cloudflare") || strings.Contains(lk, "cf-"):
			fp.CDN = "Cloudflare"
		case strings.Contains(lv, "akamai") || strings.Contains(lk, "x-amz-"):
			fp.CDN = "Akamai"
		case strings.Contains(lv, "fastly"):
			fp.CDN = "Fastly"
		case strings.Contains(lv, "maxcdn"):
			fp.CDN = "MaxCDN"
		case strings.Contains(lv, "incapsula"):
			fp.CDN = "Incapsula"
		case strings.Contains(lv, "bunny") || strings.Contains(lk, "bunnycdn"):
			fp.CDN = "BunnyCDN"
		case strings.Contains(lv, "jsdelivr"):
			fp.CDN = "jsDelivr"
		}
	}
}

// detectCMS extracts CMS information from response body and headers.
func (d *Detector) detectCMS(fp *TargetFingerprint) {
	body := strings.ToLower(fp.Body)
	for _, title := range fp.Titles {
		t := strings.ToLower(title)
		if strings.Contains(t, "wordpress") && fp.CMS == "" {
			fp.CMS = "WordPress"
			fp.TechStack["wordpress"] = true
		}
		if strings.Contains(t, "joomla") && fp.CMS == "" {
			fp.CMS = "Joomla"
			fp.TechStack["joomla"] = true
		}
		if strings.Contains(t, "drupal") && fp.CMS == "" {
			fp.CMS = "Drupal"
			fp.TechStack["drupal"] = true
		}
	}
	if strings.Contains(body, "wp-content") && fp.CMS == "" {
		fp.CMS = "WordPress"
		fp.TechStack["wordpress"] = true
	}
}

// Matches checks if a target's fingerprint matches a template's fingerprint rules.
func (d *Detector) Matches(fp *TargetFingerprint, rules []types.FingerprintRule) bool {
	if len(rules) == 0 {
		return true
	}
	for _, rule := range rules {
		if ruleMatch(fp, rule) {
			return true
		}
	}
	return false
}

// ruleMatch checks if a single fingerprint rule matches the target.
func ruleMatch(fp *TargetFingerprint, rule types.FingerprintRule) bool {
	if rule.Title != "" {
		matched := false
		for _, title := range fp.Titles {
			if contains(title, rule.Title) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if rule.Body != "" {
		if !contains(fp.Body, rule.Body) {
			return false
		}
	}

	var headerMatched bool
	if len(rule.Header) == 2 {
		key := strings.TrimSpace(rule.Header[0])
		pattern := strings.TrimSpace(rule.Header[1])
		if key != "" && pattern != "" {
			val := headerValue(fp.Headers, key)
			if matchPattern(val, pattern) {
				headerMatched = true
			}
		}
	}
	if !headerMatched {
		nonEmpty := make([]string, 0, len(rule.Header))
		for _, h := range rule.Header {
			if strings.TrimSpace(h) != "" {
				nonEmpty = append(nonEmpty, h)
			}
		}
		for _, h := range nonEmpty {
			if idx := strings.Index(h, ":"); idx >= 0 {
				key := strings.TrimSpace(h[:idx])
				pattern := strings.TrimSpace(h[idx+1:])
				if key == "" {
					continue
				}
				val := headerValue(fp.Headers, key)
				if !matchPattern(val, pattern) {
					return false
				}
			} else {
				if !headerExists(fp.Headers, h) {
					return false
				}
			}
		}
		if len(nonEmpty) > 0 {
			headerMatched = true
		}
	}

	return true
}

// GetTechStack returns the detected technology stack.
func (fp *TargetFingerprint) GetTechStack() map[string]bool {
	return fp.TechStack
}

// GetWAF returns the detected WAF name.
func (fp *TargetFingerprint) GetWAF() string {
	return fp.WAF
}

// GetCDN returns the detected CDN name.
func (fp *TargetFingerprint) GetCDN() string {
	return fp.CDN
}

// GetCMS returns the detected CMS name.
func (fp *TargetFingerprint) GetCMS() string {
	return fp.CMS
}

// GetFramework returns the detected framework name.
func (fp *TargetFingerprint) GetFramework() string {
	return fp.Framework
}

// GetServer returns the detected server name.
func (fp *TargetFingerprint) GetServer() string {
	return fp.Server
}

// GetTitles returns the detected page titles.
func (fp *TargetFingerprint) GetTitles() []string {
	return fp.Titles
}

func extractTitles(body string) []string {
	var titles []string
	lower := strings.ToLower(body)
	idx := strings.Index(lower, "<title>")
	for idx >= 0 {
		end := strings.Index(lower[idx:], "</title>")
		if end < 0 {
			break
		}
		title := strings.TrimSpace(body[idx+7 : idx+end])
		titles = append(titles, title)
		lower = lower[idx+end+8:]
		idx = strings.Index(lower, "<title>")
	}
	return titles
}

func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func headerValue(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func headerExists(headers map[string]string, key string) bool {
	for k := range headers {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

func matchPattern(val, pattern string) bool {
	pattern = strings.ReplaceAll(pattern, "*", "")
	pattern = strings.ReplaceAll(pattern, "%", "")
	return contains(val, pattern)
}

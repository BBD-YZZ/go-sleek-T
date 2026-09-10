// Package correlator 提供漏洞关联分析功能。
package correlator

import (
	"fmt"
	"strings"

	"github.com/gosleek/gosleek/pkg/types"
)

// CorrelationGroup 表示一组关联的漏洞结果。
type CorrelationGroup struct {
	// Base 是关联组的基础结果（最高严重度）。
	Base *types.Result
	// Related 是关联的其他结果。
	Related []*types.Result
	// CorrelationType 关联类型。
	CorrelationType string
	// Description 关联描述。
	Description string
}

// Correlate 对扫描结果进行关联分析。
// 返回关联组列表，每组包含一个基础结果和相关的其他结果。
func Correlate(results []*types.Result) []CorrelationGroup {
	if len(results) <= 1 {
		return nil
	}

	// 按目标分组
	byTarget := make(map[string][]*types.Result)
	for _, r := range results {
		byTarget[r.Target] = append(byTarget[r.Target], r)
	}

	var groups []CorrelationGroup

	for target, targetResults := range byTarget {
		if len(targetResults) < 2 {
			continue
		}

		// 按严重度排序
		sortBySeverity(targetResults)

		// 分析关联
		groups = append(groups, correlateByPattern(target, targetResults)...)
		groups = append(groups, correlateByTag(target, targetResults)...)
		groups = append(groups, correlateByExtraction(target, targetResults)...)
	}

	return groups
}

// correlateByPattern 基于漏洞模式关联。
func correlateByPattern(target string, results []*types.Result) []CorrelationGroup {
	var groups []CorrelationGroup

	// 关键词匹配：SQLi 相关
	sqliKeywords := []string{"sqli", "sql", "injection", "syntax error", "mysql", "postgres", "oracle"}
	// XSS 相关
	xssKeywords := []string{"xss", "cross-site", "scripting", "javascript"}
	// SSRF 相关
	ssrfKeywords := []string{"ssrf", "server side", "url", "redirect"}
	// RCE 相关
	rceKeywords := []string{"rce", "remote code", "execution", "command", "os.execute"}
	// Auth 相关
	authKeywords := []string{"auth", "login", "bypass", "credential", "token", "jwt"}

	patternGroups := map[string][]string{
		"SQL Injection Chain":  sqliKeywords,
		"XSS Chain":            xssKeywords,
		"SSRF Chain":           ssrfKeywords,
		"RCE Chain":            rceKeywords,
		"Authentication Bypass": authKeywords,
	}

	for groupName, keywords := range patternGroups {
		var matched []*types.Result
		for _, r := range results {
			if isMatchedByKeywords(r, keywords) {
				matched = append(matched, r)
			}
		}
		if len(matched) >= 2 {
			groups = append(groups, CorrelationGroup{
				Base:            matched[0],
				Related:         matched[1:],
				CorrelationType: groupName,
				Description:     formatCorrelationDescription(groupName, matched),
			})
		}
	}

	return groups
}

// correlateByTag 基于标签关联。
func correlateByTag(target string, results []*types.Result) []CorrelationGroup {
	// 找到具有相同标签的结果
	tagMap := make(map[string][]*types.Result)
	for _, r := range results {
		for _, tag := range r.Tags {
			tagMap[tag] = append(tagMap[tag], r)
		}
	}

	var groups []CorrelationGroup
	for tag, tagged := range tagMap {
		if len(tagged) >= 2 {
			groups = append(groups, CorrelationGroup{
				Base:            tagged[0],
				Related:         tagged[1:],
				CorrelationType: "Tag: " + tag,
				Description:     formatTagCorrelation(tag, tagged),
			})
		}
	}

	return groups
}

// correlateByExtraction 基于提取的数据关联。
func correlateByExtraction(target string, results []*types.Result) []CorrelationGroup {
	// 检查是否有结果提取了相同类型的数据
	extractedTypes := make(map[string][]*types.Result)
	for _, r := range results {
		for key, value := range r.Extracted {
			if len(value) > 3 { // 忽略过短的提取值
				extractedTypes[key] = append(extractedTypes[key], r)
			}
		}
	}

	var groups []CorrelationGroup
	for key, extracted := range extractedTypes {
		if len(extracted) >= 2 {
			groups = append(groups, CorrelationGroup{
				Base:            extracted[0],
				Related:         extracted[1:],
				CorrelationType: "Shared Extraction: " + key,
				Description:     formatExtractionCorrelation(key, extracted),
			})
		}
	}

	return groups
}

// isMatchedByKeywords 检查结果是否匹配关键词列表。
func isMatchedByKeywords(r *types.Result, keywords []string) bool {
	text := strings.ToLower(r.Name + " " + r.TemplateID + " " + r.Description)
	for _, kw := range keywords {
		if strings.Contains(text, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// sortBySeverity 按严重度降序排序结果。
func sortBySeverity(results []*types.Result) {
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if types.SeverityRank[strings.ToLower(results[i].Severity)] <
				types.SeverityRank[strings.ToLower(results[j].Severity)] {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
}

// formatCorrelationDescription 格式化关联描述。
func formatCorrelationDescription(groupName string, results []*types.Result) string {
	desc := groupName + " - " + results[0].Name
	if len(results) > 1 {
		desc += " + " + string(rune(results[0].Severity[0])) + " related findings"
	}
	return desc
}

// formatTagCorrelation 格式化标签关联描述。
func formatTagCorrelation(tag string, results []*types.Result) string {
	return "Common tag [" + tag + "] connecting " + fmt.Sprintf("%d", len(results)) + " findings"
}

// formatExtractionCorrelation 格式化提取数据关联描述。
func formatExtractionCorrelation(key string, results []*types.Result) string {
	return "Shared extracted data [" + key + "] across " + fmt.Sprintf("%d", len(results)) + " results"
}

// GetSummary 获取关联分析的摘要。
func GetSummary(groups []CorrelationGroup) string {
	if len(groups) == 0 {
		return "No correlations found"
	}

	var sb strings.Builder
	sb.WriteString("Correlation Analysis Summary:\n")
	sb.WriteString(strings.Repeat("=", 40) + "\n\n")

	for i, g := range groups {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, g.CorrelationType))
		sb.WriteString(fmt.Sprintf("   Base: %s [%s]\n", g.Base.Name, strings.ToUpper(g.Base.Severity)))
		if len(g.Related) > 0 {
			sb.WriteString(fmt.Sprintf("   Related: %d findings\n", len(g.Related)))
			for _, r := range g.Related {
				sb.WriteString(fmt.Sprintf("     - %s [%s]\n", r.Name, strings.ToUpper(r.Severity)))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

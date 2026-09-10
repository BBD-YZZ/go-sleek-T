package ai

import (
	"fmt"
	"strings"

	"github.com/gosleek/gosleek/pkg/types"
)

// escapeForPrompt escapes content that comes from untrusted HTTP data to prevent prompt injection.
// It truncates to maxLen bytes and removes dangerous control characters.
func escapeForPrompt(s string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			b.WriteByte(c)
		case c < 0x20:
			continue
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// BuildBatchAnalysisPrompt 构建批量 AI 漏洞分析提示词。
// 将多条漏洞结果合并到一个 prompt 中，AI 返回 JSON 数组，每条目对应一条结果。
func BuildBatchAnalysisPrompt(reqs []*AnalyzeRequest) string {
	var sb strings.Builder

	sb.WriteString("## 批量漏洞分析报告请求\n\n")
	sb.WriteString("你是专业的网络安全漏洞分析师，负责分析以下多个漏洞检测结果。\n\n")
	sb.WriteString(fmt.Sprintf("共 %d 条结果需要分析：\n\n", len(reqs)))

	for i, req := range reqs {
		sb.WriteString(fmt.Sprintf("### 结果 #%d\n\n", i+1))
		sb.WriteString(fmt.Sprintf("- **模板ID**: %s\n", req.TemplateID))
		sb.WriteString(fmt.Sprintf("- **模板名称**: %s\n", req.TemplateName))
		sb.WriteString(fmt.Sprintf("- **严重度**: %s\n", req.Severity))
		sb.WriteString(fmt.Sprintf("- **目标**: %s\n\n", req.Target))

		sb.WriteString("```http\n")
		sb.WriteString(escapeForPrompt(req.RawRequest, 4000))
		sb.WriteString("\n```\n\n")

		sb.WriteString("```http\n")
		sb.WriteString(escapeForPrompt(req.RawResponse, 4000))
		sb.WriteString("\n```\n\n")

		if req.Evidence != "" {
			sb.WriteString("**命中证据**: ")
			sb.WriteString(escapeForPrompt(req.Evidence, 1000))
			sb.WriteString("\n\n")
		}
	}

	sb.WriteString("## 输出要求\n\n")
	sb.WriteString("请以严格的 JSON 数组格式返回所有分析结果，每个元素包含以下字段：\n\n")
	sb.WriteString("```json\n")
	sb.WriteString("[\n")
	sb.WriteString(`  {"index": 0, "confident": true, "confidence": 0.95,`)
	sb.WriteString(`"evidence": "证据片段", "exploit": "验证步骤",`)
	sb.WriteString(`"impact": "影响评估", "remediation": "修复建议",`)
	sb.WriteString(`"suggestions": ["建议1", "建议2"],`)
	sb.WriteString(`"risk_assessment": "风险评估描述"}`)
	sb.WriteString(`, {"index": 1, "confident": false, "confidence": 0.3,`)
	sb.WriteString(`"evidence": "", "exploit": "",`)
	sb.WriteString(`"impact": "无法确认", "remediation": "建议人工复核",`)
	sb.WriteString(`"suggestions": ["需要进一步验证"],`)
	sb.WriteString(`"risk_assessment": "低置信度，需要人工确认"}`)
	sb.WriteString("\n]\n```\n\n")
	sb.WriteString("**注意**：\n")
	sb.WriteString("1. 必须返回与输入数量一致的 JSON 数组\n")
	sb.WriteString("2. 每个元素必须有唯一的 \"index\" 字段（从 0 开始）\n")
	sb.WriteString("3. 所有字段都必须填充有效内容\n")
	sb.WriteString("4. 响应必须是合法的 JSON 数组，不要包含 markdown 代码块\n")

	return sb.String()
}

// BuildAnalysisPrompt 构建用于 AI 漏洞分析的提示词。
// 根据请求内容生成结构化的提示，引导 AI 进行专业分析。
func BuildAnalysisPrompt(req *AnalyzeRequest) string {
	var sb strings.Builder

	// 标题
	sb.WriteString("## 漏洞分析报告请求\n\n")
	sb.WriteString(fmt.Sprintf("- **模板ID**: %s\n", req.TemplateID))
	sb.WriteString(fmt.Sprintf("- **模板名称**: %s\n", req.TemplateName))
	sb.WriteString(fmt.Sprintf("- **严重度**: %s\n", req.Severity))
	sb.WriteString(fmt.Sprintf("- **目标**: %s\n\n", req.Target))

	// 原始请求
	sb.WriteString("### 原始 HTTP 请求\n\n")
	sb.WriteString("```http\n")
	sb.WriteString(escapeForPrompt(req.RawRequest, 8000))
	sb.WriteString("\n```\n\n")

	// 原始响应
	sb.WriteString("### 原始 HTTP 响应\n\n")
	sb.WriteString("```http\n")
	sb.WriteString(escapeForPrompt(req.RawResponse, 8000))
	sb.WriteString("\n```\n\n")

	// 证据
	if req.Evidence != "" {
		sb.WriteString("### 命中证据\n\n")
		sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", req.Evidence))
	}

	// 提取数据
	if len(req.Extracted) > 0 {
		sb.WriteString("### 提取的变量\n\n")
		sb.WriteString("```json\n")
		for k, v := range req.Extracted {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, escapeForPrompt(v, 500)))
		}
		sb.WriteString("```\n\n")
	}

	// 附加上下文
	if req.Context != "" {
		sb.WriteString("### 附加上下文\n\n")
		sb.WriteString(escapeForPrompt(req.Context, 2000))
		sb.WriteString("\n\n")
	}

	// 分析指令
	sb.WriteString("## 分析任务\n\n")
	sb.WriteString("你是一个专业的网络安全漏洞分析师。请根据以下 HTTP 请求和响应内容，进行全面、深入的漏洞分析。\n\n")
	sb.WriteString("**分析要求：**\n\n")
	sb.WriteString("1. **漏洞确认**：详细分析请求/响应，判断是否存在所检测的漏洞。说明你的判断依据。\n")
	sb.WriteString("2. **漏洞证据**：从响应中提取能够证明漏洞存在的关键证据片段。\n")
	sb.WriteString("3. **验证 PoC**：提供简短的可复现验证步骤（1-2 句话），说明攻击者如何进一步确认漏洞。\n")
	sb.WriteString("4. **影响评估**：评估漏洞被利用后的实际影响范围（数据泄露、RCE、权限提升等）。\n")
	sb.WriteString("5. **修复建议**：提供具体可行的修复措施。\n")
	sb.WriteString("6. **置信度**：基于以上分析，给出你的判断置信度（0.0-1.0）。\n\n")

	// 严重度调整指引
	switch req.Severity {
	case "critical", "high":
		sb.WriteString("**注意**：这是高危/严重漏洞，请格外谨慎验证，提供详细的证据和 PoC。\n\n")
	case "medium", "low":
		sb.WriteString("**注意**：这是中低危漏洞，需要确认漏洞是否可被实际利用。\n\n")
	}

	// 添加置信度评估指引
	sb.WriteString("**置信度评估准则：**\n\n")
	sb.WriteString("- **高置信度 (0.8-1.0)**：响应中明确包含漏洞特征，如敏感数据泄露、错误信息、特定响应头、执行回显等\n")
	sb.WriteString("- **中置信度 (0.4-0.8)**：存在可疑特征但不够明确，或需要进一步验证\n")
	sb.WriteString("- **低置信度 (0.0-0.4)**：\n")
	sb.WriteString("  - 响应状态码为 4xx（如 404 Not Found、403 Forbidden）\n")
	sb.WriteString("  - 响应内容为正常页面，无漏洞特征\n")
	sb.WriteString("  - 目标不存在或不可达\n")
	sb.WriteString("  - 证据与漏洞特征明显不符\n\n")
	sb.WriteString("**重要**：如果响应状态码为 4xx 或响应内容明确表明漏洞不存在，必须给出低置信度（<0.5）。")

	sb.WriteString("## 输出格式\n\n")
	sb.WriteString("请以严格的 JSON 格式返回分析结果，必须包含以下所有字段：\n\n")
	sb.WriteString("示例（如果漏洞确实存在且证据充分）：\n\n")
	sb.WriteString("{\n")
	sb.WriteString(`  "confident": true,\n`)
	sb.WriteString(`  "confidence": 0.95,\n`)
	sb.WriteString(`  "evidence": "从响应中提取的关键证据片段",\n`)
	sb.WriteString(`  "exploit": "1. 发送特定请求 2. 验证回连或响应特征",\n`)
	sb.WriteString(`  "impact": "攻击者可完全控制系统，执行任意命令",\n`)
	sb.WriteString(`  "remediation": "升级至最新安全版本，修补相关配置",\n`)
	sb.WriteString(`  "suggestions": ["建议进一步验证步骤1", "建议进一步验证步骤2"],\n`)
	sb.WriteString(`  "risk_assessment": "Critical: OOB DNS回连确认SpEL注入成功，可完全控制系统"\n`)
	sb.WriteString("}\n\n")
	sb.WriteString("示例（如果是误报或证据不足）：\n\n")
	sb.WriteString("{\n")
	sb.WriteString(`  "confident": false,\n`)
	sb.WriteString(`  "confidence": 0.2,\n`)
	sb.WriteString(`  "evidence": "响应状态码 404，未发现漏洞特征",\n`)
	sb.WriteString(`  "exploit": "",\n`)
	sb.WriteString(`  "impact": "当前未检测到漏洞",\n`)
	sb.WriteString(`  "remediation": "无需处理，此为误报",\n`)
	sb.WriteString(`  "suggestions": ["检查请求路径是否正确", "确认目标服务是否运行"],\n`)
	sb.WriteString(`  "risk_assessment": "Low: 误报，响应中未找到漏洞证据"\n`)
	sb.WriteString("}\n\n")
	sb.WriteString("**重要**：请根据实际证据客观评估置信度，不要为了高置信度而忽略关键的反面证据。")

	return sb.String()
}

// BuildConfirmationPrompt 构建漏洞确认提示词。
// 当检测到潜在漏洞时，使用此提示词让 AI 进行二次确认，降低误报率。
func BuildConfirmationPrompt(result *types.Result, context string) string {
	var sb strings.Builder

	sb.WriteString("## 漏洞二次确认\n\n")
	sb.WriteString(fmt.Sprintf("- **模板ID**: %s\n", result.TemplateID))
	sb.WriteString(fmt.Sprintf("- **漏洞名称**: %s\n", result.Name))
	sb.WriteString(fmt.Sprintf("- **严重度**: %s\n", result.Severity))
	sb.WriteString(fmt.Sprintf("- **目标**: %s\n\n", result.Target))

	sb.WriteString("### 原始请求\n\n")
	sb.WriteString("```http\n")
	sb.WriteString(escapeForPrompt(result.RawRequest, 8000))
	sb.WriteString("\n```\n\n")

	sb.WriteString("### 原始响应\n\n")
	sb.WriteString("```http\n")
	sb.WriteString(escapeForPrompt(result.RawResponse, 8000))
	sb.WriteString("\n```\n\n")

	if result.Evidence != "" {
		sb.WriteString("### 命中证据\n\n")
		sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", result.Evidence))
	}

	if context != "" {
		sb.WriteString("### 上下文信息\n\n")
		sb.WriteString(escapeForPrompt(context, 2000))
		sb.WriteString("\n\n")
	}

	sb.WriteString("## 确认任务\n\n")
	sb.WriteString("基于以上信息，请确认：\n\n")
	sb.WriteString("1. 这是否是一个真实的漏洞？请说明理由。\n")
	sb.WriteString("2. 置信度评分是多少（0.0-1.0）？\n")
	sb.WriteString("3. 是否存在误报的可能性？如果有，请说明原因。\n\n")
	sb.WriteString("请以 JSON 格式返回：")
	sb.WriteString(`{"is_valid": true/false, "confidence": 0.0-1.0, "reason": "确认理由"}`)

	return sb.String()
}

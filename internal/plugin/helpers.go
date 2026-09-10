package plugin

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/oob"
	"github.com/gosleek/gosleek/internal/logutil"
)

// pluginOOBHandle 封装 OOBHandle 接口，委托给 oob.Provider 实现。
// 支持 ceye / dnslog / callbackred 三种 Provider。
type pluginOOBHandle struct {
	label      string
	oobURL     string
	token      string
	provider   oob.Provider
	httpClient *httpclient.Client
}

// NewOOBHandle 创建 OOB 验证句柄，支持 ceye/dnslog/callbackred。
// 推荐使用此函数替代已废弃的 NewCeyeHandle。
func NewOOBHandle(provider oob.Provider, client *httpclient.Client) OOBHandle {
	if provider == nil {
		return nil
	}
	return &pluginOOBHandle{
		label:      provider.Label(),
		oobURL:     provider.CallbackURL(),
		token:      provider.Token(),
		provider:   provider,
		httpClient: client,
	}
}

func (c *pluginOOBHandle) Label() string { return c.label }
func (c *pluginOOBHandle) URL() string   { return c.oobURL }
func (c *pluginOOBHandle) Token() string { return c.token }
func (c *pluginOOBHandle) Provider() string {
	if c.provider != nil {
		return c.provider.Name()
	}
	return ""
}

// VerifyDNS 查询 OOB Provider 是否有 DNS 回连记录。
func (c *pluginOOBHandle) VerifyDNS(ctx context.Context) (bool, error) {
	if c.provider == nil {
		return false, fmt.Errorf("OOB provider not set")
	}
	return c.provider.VerifyDNS(ctx)
}

// VerifyHTTP 查询 OOB Provider 是否有 HTTP 回连记录。
func (c *pluginOOBHandle) VerifyHTTP(ctx context.Context) (bool, error) {
	if c.provider == nil {
		return false, fmt.Errorf("OOB provider not set")
	}
	return c.provider.VerifyHTTP(ctx)
}

// pluginLogger 适配 engine.LoggerIface，实现 plugin.Logger 接口。
type pluginLogger struct {
	target string
	id     string
	inner interface {
		DebugKV(msg string, args ...interface{})
		InfoKV(msg string, args ...interface{})
		WarnKV(msg string, args ...interface{})
		Error(msg string, args ...interface{})
	}
}

// NewPluginLogger 创建插件日志器。
func NewPluginLogger(id string, inner interface {
	DebugKV(msg string, args ...interface{})
	InfoKV(msg string, args ...interface{})
	WarnKV(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}) Logger {
	return &pluginLogger{id: id, inner: inner}
}

// plugin.Logger 接口的 Info/Debug/Error 语义是 printf-style (msg 含 %s/%d, args 是参数)。
// engine.LoggerIface (InfoKV/DebugKV/Error) 的语义是 slog structured: msg 是裸文本, args 是 KV 对列表。
// 这里先 fmt.Sprintf 格式化好消息, 再把 plugin=id 作为结构化 tag 附加。
func (l *pluginLogger) Info(msg string, args ...interface{}) {
	var formatted string
	if len(args) == 0 {
		formatted = msg
	} else {
		formatted = fmt.Sprintf(msg, args...)
	}
	l.inner.InfoKV(formatted, "plugin", l.id)
}

func (l *pluginLogger) Debug(msg string, args ...interface{}) {
	var formatted string
	if len(args) == 0 {
		formatted = msg
	} else {
		formatted = fmt.Sprintf(msg, args...)
	}
	l.inner.DebugKV(formatted, "plugin", l.id)
}

func (l *pluginLogger) Error(msg string, args ...interface{}) {
	var formatted string
	if len(args) == 0 {
		formatted = msg
	} else {
		formatted = fmt.Sprintf(msg, args...)
	}
	l.inner.Error(formatted, "plugin", l.id)
}

// pluginReporter 实现 Reporter 接口，输出与 YAML 工作流一致的日志格式。
// 对接 engine 的 logger (InfoKV/DebugKV) + onPacket (Burp-style 包输出) + onRaw (匹配结果)。
type pluginReporter struct {
	id      string
	verbose int
	logger  interface {
		InfoKV(msg string, args ...interface{})
		DebugKV(msg string, args ...interface{})
		WarnKV(msg string, args ...interface{})
		Error(msg string, args ...interface{})
	}
	onPacket func(tag string, summary string, raw string)
	onRaw    func(tag string, format string, args ...interface{})
}

// NewPluginReporter 创建 Reporter 实例，注入 engine 的回调。
func NewPluginReporter(
	id string,
	verbose int,
	logger interface {
		InfoKV(msg string, args ...interface{})
		DebugKV(msg string, args ...interface{})
		WarnKV(msg string, args ...interface{})
		Error(msg string, args ...interface{})
	},
	onPacket func(tag string, summary string, raw string),
	onRaw func(tag string, format string, args ...interface{}),
) Reporter {
	return &pluginReporter{
		id:       id,
		verbose:  verbose,
		logger:   logger,
		onPacket: onPacket,
		onRaw:    onRaw,
	}
}

// LogStep 记录步骤执行开始。
func (r *pluginReporter) LogStep(stepName string, stepIndex int) {
	if r.logger != nil {
		r.logger.InfoKV("workflow step executing",
			"step", stepName, "step_index", stepIndex,
			"template", r.id)
	}
	if r.verbose >= 1 {
		logutil.Log("info", "流程", "插件[%s] 执行步骤 %s (step %d)", r.id, stepName, stepIndex)
	}
}

// LogRequest 记录 HTTP 请求，格式与 YAML 工作流一致。
func (r *pluginReporter) LogRequest(stepName string, stepIndex int, reqIndex int, raw string) {
	method, path := httpclient.ParseMethodPath(raw)

	if r.logger != nil {
		r.logger.InfoKV("workflow HTTP request sent",
			"step", stepName, "step_index", stepIndex, "req", reqIndex,
			"url", path, "method", method)
	}

	if r.verbose >= 2 && r.onPacket != nil {
		summary := fmt.Sprintf("workflow[%s] step[%d] req[%d]  %s %s  %d bytes",
			stepName, stepIndex, reqIndex, method, path, len(raw))
		r.onPacket("请求", summary, raw)
	}
}

// LogResponse 记录 HTTP 响应，格式与 YAML 工作流一致。
func (r *pluginReporter) LogResponse(stepName string, stepIndex int, reqIndex int, status int, body string, raw string, elapsed time.Duration) {
	if r.logger != nil {
		r.logger.InfoKV("workflow HTTP response received",
			"step", stepName, "step_index", stepIndex, "req", reqIndex,
			"status", status, "time_ms", elapsed.Milliseconds(),
			"bytes", len(body))
	}

	if r.verbose >= 2 && r.onPacket != nil {
		summary := fmt.Sprintf("workflow[%s] step[%d] req[%d]  status=%d  %s  %d bytes",
			stepName, stepIndex, reqIndex, status,
			elapsed.Round(time.Millisecond), len(body))
		r.onPacket("响应", summary, raw)
	}
}

// LogMatch 记录匹配结果，格式与 YAML 工作流一致。
func (r *pluginReporter) LogMatch(stepName string, stepIndex int, reqIndex int, matched bool, condition string, types []string, evidence string) {
	typesStr := strings.Join(types, ",")

	if r.logger != nil {
		if matched {
			r.logger.InfoKV("workflow matcher PASS",
				"step", stepName, "step_index", stepIndex, "req", reqIndex,
				"condition", condition,
				"types", typesStr, "evidence", evidence)
		} else {
			r.logger.InfoKV("workflow matcher FAIL",
				"step", stepName, "step_index", stepIndex, "req", reqIndex,
				"condition", condition,
				"types", typesStr)
		}
	}

	if r.verbose >= 2 && r.onRaw != nil {
		status := "FAIL"
		if matched {
			status = "PASS"
		}
		r.onRaw("匹配", "workflow[%s] step[%d] req[%d]  %s  cond=%s  types=%s  evidence=%q",
			stepName, stepIndex, reqIndex, status, condition, typesStr, evidence)
	}
	if matched && r.verbose >= 1 {
		logutil.Log("info", "匹配", "插件[%s] 步骤%s req%d 命中: types=%s evidence=%s", r.id, stepName, reqIndex, typesStr, evidence)
	}
}

// LogHTTPRequest 记录 HTTP 请求（便捷方法，自动转换 *http.Request 为 raw 格式）
func (r *pluginReporter) LogHTTPRequest(stepName string, stepIndex int, reqIndex int, req *http.Request) {
	if req == nil {
		return
	}

	// 构建原始请求字符串
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%s %s HTTP/%d.%d\r\n", req.Method, req.URL.RequestURI(), req.ProtoMajor, req.ProtoMinor))
	for key, values := range req.Header {
		for _, value := range values {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}
	buf.WriteString("\r\n")

	raw := buf.String()
	r.LogRequest(stepName, stepIndex, reqIndex, raw)
}

// LogHTTPResponse 记录 HTTP 响应（便捷方法，自动转换 *http.Response 为 raw 格式）
func (r *pluginReporter) LogHTTPResponse(stepName string, stepIndex int, reqIndex int, resp *http.Response, body string, elapsed time.Duration) {
	if resp == nil {
		return
	}

	// 构建原始响应字符串
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status))
	for key, values := range resp.Header {
		for _, value := range values {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}
	buf.WriteString("\r\n")
	buf.WriteString(body)

	raw := buf.String()
	r.LogResponse(stepName, stepIndex, reqIndex, resp.StatusCode, body, raw, elapsed)
}

// Package reporter - 真实 PDF 报告生成器 (使用 gofpdf)
package reporter

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
	"github.com/jung-kurt/gofpdf/v2"
)

// GenerateRealPDF 生成真正的 PDF 报告。
func GenerateRealPDF(results []*types.Result, scanInfo *ScanInfo, cfg *ReporterConfig, outputPath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetDisplayMode("fullpage", "continuous")

	// ── Title ──
	pdf.SetFont("Helvetica", "B", 20)
	pdf.Cell(0, 12, "gosleek Security Scan Report")
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "", 10)
	pdf.Cell(0, 6, fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02 15:04:05")))
	pdf.Ln(10)

	// ── Executive Summary ──
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 7, "Executive Summary")
	pdf.Ln(7)

	pdf.SetFont("Helvetica", "", 10)
	if scanInfo != nil {
		pdf.Cell(0, 6, fmt.Sprintf("Scan Period: %s ~ %s",
			scanInfo.StartTime.Format("2006-01-02 15:04:05"),
			scanInfo.EndTime.Format("2006-01-02 15:04:05")))
		pdf.Ln(6)
		pdf.Cell(0, 6, fmt.Sprintf("Targets: %d", len(scanInfo.Targets)))
		pdf.Ln(6)
	}
	pdf.Cell(0, 6, fmt.Sprintf("Total Findings: %d", len(results)))
	pdf.Ln(6)

	// Severity stats
	sevCount := countBySeverity(results)
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.Cell(0, 6, "Severity Distribution:")
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "", 10)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			pdf.Cell(0, 6, fmt.Sprintf("  %s: %d", strings.ToUpper(sev), count))
			pdf.Ln(6)
		}
	}
	pdf.Ln(6)

	// ── Vulnerability List ──
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 7, "Vulnerability List")
	pdf.Ln(7)

	// Table header
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetFillColor(200, 200, 200)
	pdf.SetDrawColor(150, 150, 150)
	pdf.CellFormat(10, 6, "#", "1", 0, "C", true, 0, "")
	pdf.CellFormat(20, 6, "Severity", "1", 0, "C", true, 0, "")
	pdf.CellFormat(32, 6, "Template ID", "1", 0, "C", true, 0, "")
	pdf.CellFormat(38, 6, "Name", "1", 0, "C", true, 0, "")
	pdf.CellFormat(55, 6, "Target", "1", 1, "C", true, 0, "")

	// Table data
	sortedResults := make([]*types.Result, len(results))
	copy(sortedResults, results)
	sortResultsBySeverity(sortedResults)

	pdf.SetFont("Helvetica", "", 8)
	for i, r := range sortedResults {
		name := truncate(r.Name, 20)
		target := truncate(r.Target, 42)
		tid := truncate(r.TemplateID, 28)

		pdf.CellFormat(10, 5, fmt.Sprintf("%d", i+1), "1", 0, "L", false, 0, "")
		pdf.CellFormat(20, 5, strings.ToUpper(r.Severity), "1", 0, "L", false, 0, "")
		pdf.CellFormat(32, 5, tid, "1", 0, "L", false, 0, "")
		pdf.CellFormat(38, 5, name, "1", 0, "L", false, 0, "")
		pdf.CellFormat(55, 5, target, "1", 1, "L", false, 0, "")

		// Page break every 20 rows
		if (i+1)%20 == 0 {
			pdf.AddPage()
			pdf.SetFont("Helvetica", "B", 9)
			pdf.SetFillColor(200, 200, 200)
			pdf.CellFormat(10, 6, "#", "1", 0, "C", true, 0, "")
			pdf.CellFormat(20, 6, "Severity", "1", 0, "C", true, 0, "")
			pdf.CellFormat(32, 6, "Template ID", "1", 0, "C", true, 0, "")
			pdf.CellFormat(38, 6, "Name", "1", 0, "C", true, 0, "")
			pdf.CellFormat(55, 6, "Target", "1", 1, "C", true, 0, "")
			pdf.SetFont("Helvetica", "", 8)
		}
	}

	// ── Vulnerability Details ──
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 7, "Vulnerability Details")
	pdf.Ln(7)

	for i, r := range sortedResults {
		pdf.SetFont("Helvetica", "B", 10)
		title := fmt.Sprintf("%d. %s [%s]", i+1, r.Name, strings.ToUpper(r.Severity))
		pdf.Cell(0, 6, title)
		pdf.Ln(6)
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(0, 4,
			fmt.Sprintf("Template: %s\nTarget:   %s\nEvidence: %s",
				r.TemplateID, r.Target, truncate(r.Evidence, 180)),
			"", "", false)
		pdf.Ln(3)
	}

	// ── Remediation ──
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 7, "Remediation Recommendations")
	pdf.Ln(7)

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			pdf.SetFont("Helvetica", "B", 10)
			pdf.Cell(0, 6, fmt.Sprintf("%s Vulnerability (%d findings)", strings.ToUpper(sev), count))
			pdf.Ln(6)
			pdf.SetFont("Helvetica", "", 9)
			pdf.MultiCell(0, 5, getRemediationForSeverity(sev), "", "", false)
			pdf.Ln(4)
		}
	}

	return pdf.OutputFileAndClose(outputPath)
}

// GeneratePDF 创建真正的 PDF 报告（委托给 GenerateRealPDF）。
func (r *Reporter) GeneratePDF(ctx context.Context, results []*types.Result, scanInfo *ScanInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return GenerateRealPDF(results, scanInfo, &ReporterConfig{
		Title:   r.title,
		Author:  r.author,
		Version: r.version,
	}, r.outputDir+"/report.pdf")
}

// GenerateChinesePDF 生成带中文支持的 PDF 报告（需要中文字体文件）。
// 如果字体文件不可用，降级为英文 PDF。
func GenerateChinesePDF(results []*types.Result, scanInfo *ScanInfo, cfg *ReporterConfig, outputPath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetDisplayMode("fullpage", "continuous")

	// Try to load Chinese font
	fontData := loadChineseFont()
	if len(fontData) > 0 {
		pdf.AddFontFromReader("Chinese", "", strings.NewReader(string(fontData)))
	}

	// ── Title ──
	if len(fontData) > 0 {
		pdf.SetFont("Chinese", "B", 20)
		pdf.Cell(0, 12, "gosleek 安全扫描报告")
	} else {
		pdf.SetFont("Helvetica", "B", 20)
		pdf.Cell(0, 12, "gosleek Security Scan Report")
	}
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "", 10)
	pdf.Cell(0, 6, fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02 15:04:05")))
	pdf.Ln(10)

	// ── Executive Summary ──
	pdf.SetFont("Helvetica", "B", 12)
	if len(fontData) > 0 {
		pdf.SetFont("Chinese", "B", 12)
		pdf.Cell(0, 7, "执行摘要")
	} else {
		pdf.Cell(0, 7, "Executive Summary")
	}
	pdf.Ln(7)

	pdf.SetFont("Helvetica", "", 10)
	if scanInfo != nil {
		pdf.Cell(0, 6, fmt.Sprintf("Scan Period: %s ~ %s",
			scanInfo.StartTime.Format("2006-01-02 15:04:05"),
			scanInfo.EndTime.Format("2006-01-02 15:04:05")))
		pdf.Ln(6)
		pdf.Cell(0, 6, fmt.Sprintf("Targets: %d", len(scanInfo.Targets)))
		pdf.Ln(6)
	}
	pdf.Cell(0, 6, fmt.Sprintf("Total Findings: %d", len(results)))
	pdf.Ln(6)

	// Severity stats
	sevCount := countBySeverity(results)
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.Cell(0, 6, "Severity Distribution:")
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "", 10)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			pdf.Cell(0, 6, fmt.Sprintf("  %s: %d", strings.ToUpper(sev), count))
			pdf.Ln(6)
		}
	}
	pdf.Ln(6)

	// ── Vulnerability List ──
	pdf.SetFont("Helvetica", "B", 12)
	if len(fontData) > 0 {
		pdf.SetFont("Chinese", "B", 12)
		pdf.Cell(0, 7, "漏洞清单")
	} else {
		pdf.Cell(0, 7, "Vulnerability List")
	}
	pdf.Ln(7)

	// Table header
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetFillColor(200, 200, 200)
	pdf.SetDrawColor(150, 150, 150)
	pdf.CellFormat(10, 6, "#", "1", 0, "C", true, 0, "")
	pdf.CellFormat(20, 6, "Severity", "1", 0, "C", true, 0, "")
	pdf.CellFormat(32, 6, "Template ID", "1", 0, "C", true, 0, "")
	pdf.CellFormat(38, 6, "Name", "1", 0, "C", true, 0, "")
	pdf.CellFormat(55, 6, "Target", "1", 1, "C", true, 0, "")

	// Table data
	sortedResults := make([]*types.Result, len(results))
	copy(sortedResults, results)
	sortResultsBySeverity(sortedResults)

	pdf.SetFont("Helvetica", "", 8)
	for i, r := range sortedResults {
		name := truncate(r.Name, 20)
		target := truncate(r.Target, 42)
		tid := truncate(r.TemplateID, 28)

		pdf.CellFormat(10, 5, fmt.Sprintf("%d", i+1), "1", 0, "L", false, 0, "")
		pdf.CellFormat(20, 5, strings.ToUpper(r.Severity), "1", 0, "L", false, 0, "")
		pdf.CellFormat(32, 5, tid, "1", 0, "L", false, 0, "")
		pdf.CellFormat(38, 5, name, "1", 0, "L", false, 0, "")
		pdf.CellFormat(55, 5, target, "1", 1, "L", false, 0, "")

		// Page break every 20 rows
		if (i+1)%20 == 0 {
			pdf.AddPage()
			pdf.SetFont("Helvetica", "B", 9)
			pdf.SetFillColor(200, 200, 200)
			pdf.CellFormat(10, 6, "#", "1", 0, "C", true, 0, "")
			pdf.CellFormat(20, 6, "Severity", "1", 0, "C", true, 0, "")
			pdf.CellFormat(32, 6, "Template ID", "1", 0, "C", true, 0, "")
			pdf.CellFormat(38, 6, "Name", "1", 0, "C", true, 0, "")
			pdf.CellFormat(55, 6, "Target", "1", 1, "C", true, 0, "")
			pdf.SetFont("Helvetica", "", 8)
		}
	}

	// ── Remediation ──
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 12)
	if len(fontData) > 0 {
		pdf.SetFont("Chinese", "B", 12)
		pdf.Cell(0, 7, "修复建议")
	} else {
		pdf.Cell(0, 7, "Remediation Recommendations")
	}
	pdf.Ln(7)

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			pdf.SetFont("Helvetica", "B", 10)
			pdf.Cell(0, 6, fmt.Sprintf("%s Vulnerability (%d findings)", strings.ToUpper(sev), count))
			pdf.Ln(6)
			pdf.SetFont("Helvetica", "", 9)
			pdf.MultiCell(0, 5, getRemediationForSeverity(sev), "", "", false)
			pdf.Ln(4)
		}
	}

	return pdf.OutputFileAndClose(outputPath)
}

// loadChineseFont 查找中文字体文件。
func loadChineseFont() []byte {
	candidates := []string{
		"embeds/simhei.ttf",
		"embeds/simsun.ttc",
		"/c/Windows/Fonts/simhei.ttf",
		"/c/Windows/Fonts/simsun.ttc",
		"C:\\Windows\\Fonts\\simhei.ttf",
		"C:\\Windows\\Fonts\\simsun.ttc",
	}
	for _, path := range candidates {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return data
		}
	}
	return nil
}

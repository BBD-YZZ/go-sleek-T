package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResumeStateSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	resumePath := filepath.Join(tmpDir, "resume.json")

	rs := NewResumeState(resumePath)
	if rs == nil {
		t.Fatal("NewResumeState returned nil")
	}

	// 标记一些任务完成
	rs.MarkDone("http://example.com", "template-1")
	rs.MarkDone("http://example.com", "template-2")
	rs.MarkDone("http://test.com", "template-1")

	// 保存
	if err := rs.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// 验证文件存在
	if _, err := os.Stat(resumePath); os.IsNotExist(err) {
		t.Fatal("Resume file not created")
	}

	// 重新加载
	rs2 := NewResumeState(resumePath)
	if rs2 == nil {
		t.Fatal("NewResumeState returned nil after reload")
	}

	// 验证加载的结果
	if !rs2.IsDone("http://example.com", "template-1") {
		t.Error("Expected template-1 to be done for example.com")
	}
	if !rs2.IsDone("http://example.com", "template-2") {
		t.Error("Expected template-2 to be done for example.com")
	}
	if !rs2.IsDone("http://test.com", "template-1") {
		t.Error("Expected template-1 to be done for test.com")
	}
	if rs2.IsDone("http://test.com", "template-2") {
		t.Error("Expected template-2 to NOT be done for test.com")
	}
}

func TestResumeSeparatorConsistency(t *testing.T) {
	rs := NewResumeState("")

	target := "http://example.com"
	templateID := "test-template"

	// 使用 MarkDone（应与 runJob 中的分隔符一致）
	rs.MarkDone(target, templateID)

	// 验证可以正确查询
	if !rs.IsDone(target, templateID) {
		t.Errorf("Expected task to be marked as done")
	}

	// 验证 Completed 字段中的分隔符格式
	rs.mu.Lock()
	if len(rs.Completed) != 1 {
		t.Fatalf("Expected 1 completed pair, got %d", len(rs.Completed))
	}

	expectedKey := target + ":::" + templateID
	if rs.Completed[0] != expectedKey {
		t.Errorf("Expected key %q, got %q", expectedKey, rs.Completed[0])
	}
	rs.mu.Unlock()
}

func TestResumeFilterPending(t *testing.T) {
	rs := NewResumeState("")

	// 标记 http://example.com 的所有模板都完成
	rs.MarkDone("http://example.com", "template-1")
	rs.MarkDone("http://example.com", "template-2")
	rs.MarkDone("http://example.com", "template-3")
	// 标记 http://test.com 的部分模板完成
	rs.MarkDone("http://test.com", "template-1")

	targets := []string{"http://example.com", "http://test.com", "http://other.com"}
	templates := []string{"template-1", "template-2", "template-3"}

	pendingTargets, pendingTemplates := rs.FilterPending(targets, templates)

	// http://example.com 的所有模板都完成了，应该被过滤掉
	for _, tgt := range pendingTargets {
		if tgt == "http://example.com" {
			t.Error("http://example.com should be filtered out (all templates done)")
		}
	}

	// http://test.com 还有 template-2 和 template-3 未完成
	found := false
	for _, tgt := range pendingTargets {
		if tgt == "http://test.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("http://test.com should be in pending targets")
	}

	// http://other.com 完全未扫描
	found = false
	for _, tgt := range pendingTargets {
		if tgt == "http://other.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("http://other.com should be in pending targets")
	}

	// 验证模板过滤
	// template-1 应该在 http://test.com 和 http://other.com 中
	// template-2 和 template-3 应该在 http://test.com 和 http://other.com 中
	for _, tmpl := range pendingTemplates {
		if tmpl != "template-1" && tmpl != "template-2" && tmpl != "template-3" {
			t.Errorf("Unexpected template: %s", tmpl)
		}
	}
}

func TestResumeClear(t *testing.T) {
	tmpDir := t.TempDir()
	resumePath := filepath.Join(tmpDir, "resume.json")

	rs := NewResumeState(resumePath)
	rs.MarkDone("http://example.com", "template-1")

	// Clear 应该清除文件
	if err := rs.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if err := rs.Clear(); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// 文件应该被删除
	if _, err := os.Stat(resumePath); !os.IsNotExist(err) {
		t.Error("Resume file should be deleted after Clear")
	}
}

func TestParseTargetTemplateIDs(t *testing.T) {
	items := []string{
		"http://example.com:::template-1",
		"http://test.com:::template-2",
	}

	targets, templateIDs := ParseTargetTemplateIDs(items)

	if len(targets) != 2 {
		t.Errorf("Expected 2 targets, got %d", len(targets))
	}
	if len(templateIDs) != 2 {
		t.Errorf("Expected 2 templateIDs, got %d", len(templateIDs))
	}

	if targets[0] != "http://example.com" {
		t.Errorf("Expected 'http://example.com', got %q", targets[0])
	}
	if templateIDs[0] != "template-1" {
		t.Errorf("Expected 'template-1', got %q", templateIDs[0])
	}
}

func TestSplitPair(t *testing.T) {
	target, templateID := SplitPair("http://example.com:::template-1")

	if target != "http://example.com" {
		t.Errorf("Expected 'http://example.com', got %q", target)
	}
	if templateID != "template-1" {
		t.Errorf("Expected 'template-1', got %q", templateID)
	}

	// 测试无效格式
	target, templateID = SplitPair("invalid-format")
	if target != "invalid-format" {
		t.Errorf("Expected 'invalid-format', got %q", target)
	}
	if templateID != "" {
		t.Errorf("Expected empty templateID, got %q", templateID)
	}
}

func TestResumeSummary(t *testing.T) {
	rs := NewResumeState("")

	rs.MarkDone("http://example.com", "template-1")
	rs.MarkDone("http://example.com", "template-2")
	rs.MarkDone("http://test.com", "template-1")

	summary := rs.Summary()
	if summary == "" {
		t.Error("Summary should not be empty")
	}
}

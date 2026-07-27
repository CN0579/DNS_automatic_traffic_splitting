package util

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadFileRemovesTempOnValidationFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("bad payload"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "geoip.dat")

	err := DownloadFile(dst, srv.URL, func(string) error {
		return fmt.Errorf("boom")
	})
	if err == nil {
		t.Fatal("期望校验失败返回错误")
	}

	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("校验失败后临时文件应被删除，got err=%v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("校验失败后不应产生目标文件")
	}
}

func TestDownloadFileRejectsEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "geoip.dat")

	// 空响应必须被拒绝：旧实现会把一个 0 字节文件 rename 到位，
	// 覆盖掉原本可用的 Geo 数据库。
	if err := DownloadFile(dst, srv.URL, nil); err == nil {
		t.Fatal("期望空响应体返回错误")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("空响应不应覆盖/创建目标文件")
	}
}

func TestDownloadFileEnforcesSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 1<<20)
		for i := 0; i < (maxDownloadSize>>20)+2; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "big.dat")

	err := DownloadFile(dst, srv.URL, nil)
	if err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("期望超限错误，got %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("超限下载不应产生目标文件")
	}
}

func TestDownloadFileSucceedsAndReplaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("new content"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(dst, []byte("old content"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := DownloadFile(dst, srv.URL, nil); err != nil {
		t.Fatalf("下载失败: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new content" {
		t.Errorf("目标文件内容 = %q, want %q", got, "new content")
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Error("成功后临时文件应已被 rename 消耗")
	}
}

func TestDownloadFileRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "geoip.dat")

	if err := DownloadFile(dst, srv.URL, nil); err == nil {
		t.Fatal("期望 404 返回错误")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("失败下载不应创建目标文件")
	}
}

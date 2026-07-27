package util

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Validator func(string) error

// maxDownloadSize 限制单个 Geo 数据文件的下载体积。
// 不设上限时，一个坏掉或恶意的下载源可以持续吐数据直到写满磁盘。
const maxDownloadSize = 512 << 20

// downloadClient 带总超时。http.DefaultClient 没有任何超时，
// 上游若在 TCP 层挂起，自动更新 goroutine 会永久阻塞在这里，
// 之后所有计划内的 Geo 更新都不再发生。
var downloadClient = &http.Client{Timeout: 10 * time.Minute}

func DownloadFile(path string, url string, validator Validator) error {
	// 临时文件放在目标同目录，保证 rename 是同一文件系统内的原子操作。
	tempFile := path + ".tmp"

	out, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("无法创建临时文件: %w", err)
	}

	renamed := false
	defer func() {
		out.Close()
		if !renamed {
			os.Remove(tempFile)
		}
	}()

	resp, err := downloadClient.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，HTTP 状态码: %s", resp.Status)
	}

	// 多读 1 字节用于判断是否超限，避免把超大响应整个落盘后才发现。
	written, err := io.Copy(out, io.LimitReader(resp.Body, maxDownloadSize+1))
	if err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}
	if written > maxDownloadSize {
		return fmt.Errorf("下载内容超过 %d 字节上限", int64(maxDownloadSize))
	}
	if written == 0 {
		return fmt.Errorf("下载内容为空")
	}

	// 先 fsync 再 rename：否则断电/崩溃后可能留下一个大小正确但内容为空洞的
	// 文件，而 rename 已经生效，下次启动会加载到损坏的 Geo 数据。
	if err := out.Sync(); err != nil {
		return fmt.Errorf("同步文件失败: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("关闭文件失败: %w", err)
	}

	if validator != nil {
		if err := validator(tempFile); err != nil {
			return fmt.Errorf("文件校验失败: %w", err)
		}
	}

	// renamed 必须在 Rename 成功之后再置位，
	// 否则重命名失败时 defer 不会清理，临时文件被永久遗留。
	if err := os.Rename(tempFile, path); err != nil {
		return fmt.Errorf("重命名文件失败: %w", err)
	}
	renamed = true

	// 同步目录项，确保 rename 本身也已落盘。
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		dir.Sync()
		dir.Close()
	}

	return nil
}

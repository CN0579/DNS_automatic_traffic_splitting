package util

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

type Validator func(string) error

func DownloadFile(filepath string, url string, validator Validator) error {
	tempFile := filepath + ".tmp"

	out, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("无法创建临时文件: %w", err)
	}

	success := false
	defer func() {
		out.Close()
		if !success {
			os.Remove(tempFile)
		}
	}()

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，HTTP 状态码: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	out.Close()

	if validator != nil {
		if err := validator(tempFile); err != nil {
			return fmt.Errorf("文件校验失败: %w", err)
		}
	}

	success = true

	if err := os.Rename(tempFile, filepath); err != nil {
		return fmt.Errorf("重命名文件失败: %w", err)
	}

	return nil
}

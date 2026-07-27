package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/manager"
	"doh-autoproxy/internal/web"
)

func main() {
	fmt.Println("DoH Automatic Traffic Splitting Service is starting...")

	configPath := config.GetDefaultConfigPath()
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("无法加载配置: %v", err)
	}

	log.Println("配置加载成功")

	svcMgr := manager.NewServiceManager(cfg)

	svcMgr.CheckAndDownloadGeoFiles()

	if err := svcMgr.Start(); err != nil {
		log.Fatalf("Failed to start services: %v", err)
	}

	web.StartWebServer(svcMgr)

	log.Println("所有服务已启动")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("收到关闭信号，正在停止服务...")
	if err := svcMgr.Stop(); err != nil {
		log.Printf("停止服务时出错: %v", err)
	}
	log.Println("服务已停止")
}

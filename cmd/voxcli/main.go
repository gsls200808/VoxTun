package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"voxTun/internal/app/client"
	"voxTun/internal/app/common/config"
	"voxTun/internal/app/common/util"
)

func main() {
	configPath := flag.String("c", "configs/voxcli.yaml", "配置文件路径")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config failed:", err)
		os.Exit(1)
	}
	if err := util.InitLogger(cfg.LogLevel); err != nil {
		fmt.Fprintln(os.Stderr, "init logger failed:", err)
		os.Exit(1)
	}
	defer util.Sync()

	cli := client.NewClient(cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		util.Logger.Infow("shutting down")
		cli.Close()
	}()

	if err := cli.Run(); err != nil {
		util.Logger.Errorw("client run", "err", err)
		os.Exit(1)
	}
}

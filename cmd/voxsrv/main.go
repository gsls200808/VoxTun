package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"voxTun/internal/app/common/config"
	"voxTun/internal/app/common/util"
	"voxTun/internal/app/server"
)

func main() {
	configPath := flag.String("c", "configs/voxsrv.yaml", "配置文件路径")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config failed:", err)
		os.Exit(1)
	}
	if err := util.InitLogger(cfg.LogLevel); err != nil {
		fmt.Fprintln(os.Stderr, "init logger failed:", err)
		os.Exit(1)
	}
	defer util.Sync()

	srv, err := server.NewServer(cfg)
	if err != nil {
		util.Logger.Fatalw("init server", "err", err)
	}

	go func() {
		if err := srv.Run(); err != nil {
			util.Logger.Fatalw("server run", "err", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	util.Logger.Infow("shutting down")
	srv.Shutdown()
}

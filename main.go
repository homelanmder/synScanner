package main

import (
	"crypto/tls"
	"flag"
	"github.com/homelanmder/synScanner/common"
	"github.com/homelanmder/synScanner/plugin"
	"github.com/homelanmder/synScanner/scan"
	"github.com/valyala/fasthttp"
	"net"
	"time"
)

func main() {
	var ports string
	var ips string
	flag.StringVar(&ports, "p", common.DefaultPort, "指定目的端口")
	flag.StringVar(&common.InterfaceName, "i", "ens33", "指定网卡名称，使用该网卡发送syn")
	flag.StringVar(&ips, "ip", "", "指定ip")
	flag.IntVar(&common.Thread, "t", 500, "指定线程")
	flag.IntVar(&common.Timeout, "timeout", 3, "指定超时时间")
	flag.StringVar(&common.TaskName, "task", "", "指定任务名")
	flag.IntVar(&common.LocalPort, "lp", 8888, "指定本地端口")
	flag.StringVar(&common.InteractIp, "in", "", "指定回连地址")
	flag.Parse()
	if ips == "" {
		flag.Usage()
		return
	}

	common.HttpClient = &fasthttp.Client{
		ReadTimeout:                   time.Duration(common.Timeout) * time.Second,
		WriteTimeout:                  time.Duration(common.Timeout) * time.Second,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		MaxIdleConnDuration:           0,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
		Dial: func(addr string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: time.Duration(common.Timeout) * time.Second,
			}
			conn, err := dialer.Dial(common.Tcp, addr)
			return conn, err
		},
	}
	if common.InteractIp == "" {
		common.InteractIp = common.LocalIp
	}
	go plugin.Run()
	scan.Scan(ips, ports)

}

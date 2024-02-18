package plugin

import (
	"fmt"
	"net"
	"strings"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func ZookeeperConn(hostInfo *common.HostInfo) {
	var err error
	var length int
	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	conn, err := net.DialTimeout(common.Tcp, host, time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return
	}
	if _, err = conn.Write([]byte("envi")); err != nil {
		return
	}
	data := make([]byte, 128)
	if length, err = conn.Read(data); err != nil {
		return
	}
	if strings.Contains(string(data[:length]), "Environment:") {
		now := time.Now()
		vul := common.Vul{
			CreateTime:     now,
			VulName:        common.ZookeeperUnauthenticatedLogin,
			Host:           host,
			Ip:             hostInfo.IP,
			Port:           hostInfo.Port,
			VulLevel:       common.HighLevel,
			VulType:        common.WeakPassType,
			Description:    common.ZookeeperUnauthenticatedDescription,
			Remediation:    common.UnauthenticatedRemediation,
			LatestFindTime: now,
		}
		common.SaveVulInfo(vul)
		fmt.Println(vul)
	}
	conn.Close()

}

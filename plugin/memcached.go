package plugin

import (
	"fmt"
	"net"
	"strings"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func MemcachedConn(hostInfo *common.HostInfo) {
	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	client, err := net.DialTimeout(common.Tcp, host, time.Duration(common.Timeout)*time.Second)
	if err == nil {
		err = client.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
		if err == nil {
			_, err = client.Write([]byte("stats\n")) //Set the key randomly to prevent the key on the server from being overwritten
			if err == nil {
				rev := make([]byte, 1024)
				n, err := client.Read(rev)
				if err != nil {
					return
				}
				if strings.Contains(string(rev[:n]), "STAT") {
					now := time.Now()
					vulInfo := common.Vul{
						CreateTime:     now,
						VulLevel:       common.HighLevel,
						VulName:        common.MemcachedUnauthenticatedLogin,
						VulType:        common.WeakPassType,
						Description:    common.MemcachedUnauthenticatedDescription,
						Remediation:    common.UnauthenticatedRemediation,
						Host:           host,
						Ip:             hostInfo.IP,
						Port:           hostInfo.Port,
						LatestFindTime: now,
					}
					common.SaveVulInfo(vulInfo)
					fmt.Println(vulInfo)
				}
			}
		}
	}
}

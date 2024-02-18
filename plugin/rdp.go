package plugin

import (
	"fmt"
	"time"
	"github.com/homelanmder/synScanner/common"
	"github.com/homelanmder/synScanner/pkg/grdp"
)

func RdpConn(hostInfo *common.HostInfo) {

	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)

	for _, username := range common.UserDict[common.Rdp] {
		for _, password := range common.Passwords {
			if err := rdpLogin(host, username, password); err == nil {
				now := time.Now()
				vulInfo := common.Vul{
					CreateTime:  now,
					VulLevel:    common.HighLevel,
					VulName:     common.RdpWeakPass,
					VulType:     common.WeakPassType,
					Description: common.RdpWeakPassDescription,
					Remediation: common.WeakPassRemediation,
					Host:        fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port),
					Ip:          hostInfo.IP,
					Port:        hostInfo.Port,
					WeakPass: common.UserPassDict{
						UserName: username,
						PassWord: password,
					},
					LatestFindTime: now,
				}
				common.SaveVulInfo(vulInfo)
				break
			}
		}
	}
}

func rdpLogin(host, username, password string) error {
	var err error
	protocol := grdp.VerifyProtocol(host)
	if protocol == grdp.PROTOCOL_SSL {
		err = grdp.LoginForSSL(host, "", username, password)
	} else {
		err = grdp.LoginForRDP(host, "", username, password)
	}
	if err != nil {
		return err
	}
	return err
}

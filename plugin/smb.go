package plugin

import (
	"fmt"
	"github.com/stacktitan/smb/smb"
	"strconv"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func SmbConn(hostInfo *common.HostInfo) {

	for _, username := range common.UserDict[common.Smb] {
		for _, password := range common.Passwords {
			if err := smbLogin(hostInfo.IP, hostInfo.Port, username, password); err == nil {
				now := time.Now()
				vulInfo := common.Vul{
					CreateTime:  now,
					VulLevel:    common.HighLevel,
					VulName:     common.SmbWeakPass,
					VulType:     common.WeakPassType,
					Description: common.SmbWeakPassDescription,
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
				fmt.Println(vulInfo)
				break
			}
		}
	}
}

func smbLogin(ip, p, username, password string) error {
	port, _ := strconv.Atoi(p)
	options := smb.Options{
		Host:        ip,
		Port:        port,
		User:        username,
		Password:    password,
		Domain:      ".",
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err != nil {
		return err
	}
	session.Close()
	return nil
}

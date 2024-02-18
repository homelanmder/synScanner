package plugin

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"github.com/homelanmder/synScanner/common"
	"time"
)

func SshConn(hostInfo *common.HostInfo) {

	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	for _, username := range common.UserDict[common.Ssh] {
		for _, password := range common.Passwords {
			start := time.Now().Unix()
			if err := sshLogin(host, username, password); err == nil {
				now := time.Now()
				vulInfo := common.Vul{
					CreateTime:  now,
					VulLevel:    common.HighLevel,
					VulName:     common.SshWeakPass,
					VulType:     common.WeakPassType,
					Description: common.SSHWeakPassDescription,
					Remediation: common.WeakPassRemediation,
					Host:        host,
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
			end := time.Now().Unix()
			fmt.Println("爆破一次花费时间", end-start)
		}
	}

}

func sshLogin(host, username, password string) error {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(common.Timeout) * time.Second,
	}

	client, err := ssh.Dial(common.Tcp, host, config)
	if err != nil {
		//fmt.Println(err.Error(), userPass.UserName, userPass.PassWord)
		return err
	}
	client.Close()
	return nil
}

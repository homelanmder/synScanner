package plugin

import (
	"fmt"
	"net"
	"strings"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func RedisConn(hostInfo *common.HostInfo) {
	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	for _, password := range common.Passwords {
		if vulType, success, err := auth(host, password); err == nil && success {
			var vulDescription string
			var vulRemediation string
			var userPass common.UserPassDict
			now := time.Now()
			switch vulType {
			case common.RedisWeakPass:
				vulDescription = common.RedisWeakPassDescription
				vulRemediation = common.WeakPassRemediation
				userPass.PassWord = password
			case common.RedisUnauthenticatedLogin:
				vulDescription = common.RedisUnauthenticatedDescription
				vulRemediation = common.UnauthenticatedRemediation
			}
			vulInfo := common.Vul{
				CreateTime:     now,
				VulLevel:       common.HighLevel,
				VulName:        vulType,
				VulType:        common.WeakPassType,
				Description:    vulDescription,
				Remediation:    vulRemediation,
				Host:           host,
				Ip:             hostInfo.IP,
				Port:           hostInfo.Port,
				WeakPass:       userPass,
				LatestFindTime: now,
			}
			common.SaveVulInfo(vulInfo)
			fmt.Println(vulInfo)
			return
		}
	}

}

func auth(host, password string) (vulType string, success bool, err error) {
	conn, err := net.DialTimeout(common.Tcp, host, time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return "", false, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	if err != nil {
		return "", false, err
	}

	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", password)))
	if err != nil {
		return "", false, err
	}
	var reply string
	size := 5 * 1024
	buf := make([]byte, size)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		reply += string(buf[0:count])
		if count < size {
			break
		}
	}
	conn.Close()
	if strings.Contains(reply, "redis_version") {
		return common.RedisWeakPass, true, nil
	} else if strings.Contains(reply, "no password is set") {
		return common.RedisUnauthenticatedLogin, true, nil
	}
	return "", false, nil
}

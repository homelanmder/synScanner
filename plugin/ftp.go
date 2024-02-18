package plugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/jlaffaye/ftp"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func FtpConn(hostInfo *common.HostInfo) {

	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	//首先进行未授权访问检测,如果未授权访问成功,则不进行弱口令检测
	anonymousDict := common.UserPassDict{
		UserName: "anonymous",
		PassWord: "anonymous",
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(common.Timeout)*time.Second)
	err := ftpWithContext(ctx, host, anonymousDict)
	cancel()
	if err == nil {
		now := time.Now()
		vulInfo := common.Vul{
			CreateTime:     now,
			VulLevel:       common.HighLevel,
			VulName:        common.FtpAnonymousLogin,
			VulType:        common.WeakPassType,
			Description:    common.AnonymousRemediation,
			Remediation:    common.FtpAnonymousDescription,
			Host:           host,
			Ip:             hostInfo.IP,
			Port:           hostInfo.Port,
			WeakPass:       anonymousDict,
			LatestFindTime: now,
		}
		common.SaveVulInfo(vulInfo)
		fmt.Println(vulInfo)
		return
	} else {
		for _, username := range common.UserDict[common.Ftp] {
			for _, password := range common.Passwords {

				userPass := common.UserPassDict{
					UserName: username,
					PassWord: password,
				}
				ctxBurst, cancelBurst := context.WithTimeout(context.Background(), time.Duration(common.Timeout)*time.Second)
				e := ftpWithContext(ctxBurst, host, userPass)
				cancelBurst()
				if e == nil {
					now := time.Now()
					vulInfo := common.Vul{
						CreateTime:     now,
						VulLevel:       common.HighLevel,
						VulName:        common.FtpWeakPass,
						VulType:        common.WeakPassType,
						Description:    common.FtpWeakPassDescription,
						Remediation:    common.WeakPassRemediation,
						Host:           host,
						Ip:             hostInfo.IP,
						Port:           hostInfo.Port,
						WeakPass:       userPass,
						LatestFindTime: now,
					}
					common.SaveVulInfo(vulInfo)
					fmt.Println(vulInfo)
					break
				}
			}
		}
	}

}

func ftpWithContext(ctx context.Context, host string, userPass common.UserPassDict) error {
	c := make(chan error, 1)
	go func() {
		conn, err := ftp.Dial(host)
		if err != nil {
			c <- err
			return
		}
		defer conn.Quit()
		err = conn.Login(userPass.UserName, userPass.PassWord)
		if err != nil {
			c <- err
			return
		}
		c <- nil
	}()

	select {
	case <-ctx.Done():
		return errors.New("ftp连接超时")
	case err := <-c:
		return err
	}
}

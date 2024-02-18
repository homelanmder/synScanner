package plugin

import (
	"database/sql"
	"fmt"
	_ "github.com/sijms/go-ora/v2"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func OracleConn(hostInfo *common.HostInfo) {
	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	for _, username := range common.UserDict[common.Oracle] {
		for _, password := range common.Passwords {
			if err := oracleLogin(host, username, password); err == nil {
				now := time.Now()
				vulInfo := common.Vul{
					CreateTime:  now,
					VulLevel:    common.HighLevel,
					VulName:     common.OracleWeakPass,
					VulType:     common.WeakPassType,
					Description: common.OracleWeakPassDescription,
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
		}
	}
}

func oracleLogin(host, username, password string) error {
	dataSourceName := fmt.Sprintf("oracle://%s:%s@%s/orcl", username, password, host)
	db, err := sql.Open("oracle", dataSourceName)
	if err != nil {
		return err
	}
	if err = db.Ping(); err != nil {
		return err
	}
	db.Close()
	return nil
}

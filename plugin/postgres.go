package plugin

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func PostgresConn(hostInfo *common.HostInfo) {
	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	for _, username := range common.UserDict[common.Postgresql] {
		for _, password := range common.Passwords {
			if err := postgresLogin(host, username, password); err == nil {
				now := time.Now()
				vulInfo := common.Vul{
					CreateTime:  now,
					VulLevel:    common.HighLevel,
					VulName:     common.PostgresqlWeakPass,
					VulType:     common.WeakPassType,
					Description: common.PostgresqlWeakPassDescription,
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

func postgresLogin(host, username, password string) error {
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v/%v?sslmode=%v", username, password, host, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return err
	}

	if err = db.Ping(); err != nil {
		return err
	}
	db.Close()
	return nil
}

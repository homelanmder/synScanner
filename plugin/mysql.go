package plugin

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func MysqlConn(hostInfo *common.HostInfo) {

	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)

	for _, username := range common.UserDict[common.Mysql] {
		for _, password := range common.Passwords {

			if err := mysqlLogin(host, username, password); err == nil {
				now := time.Now()
				vulInfo := common.Vul{
					CreateTime:  now,
					VulLevel:    common.HighLevel,
					VulName:     common.MysqlWeakPass,
					VulType:     common.WeakPassType,
					Description: common.MysqlWeakPassDescription,
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

func mysqlLogin(host, username, password string) error {
	dataSourceName := fmt.Sprintf("%s:%s@tcp(%s)/mysql?charset=utf8&timeout=%v", username, password, host, time.Duration(common.Timeout)*time.Second)
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return err
	}
	if err = db.Ping(); err != nil {
		return err
	}
	db.Close()
	return nil
}

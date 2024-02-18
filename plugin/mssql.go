package plugin

import (
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func MssqlConn(hostInfo *common.HostInfo) {

	defer func() {
		if e := recover(); e != nil {
			fmt.Println(e)
		}
	}()
	for _, username := range common.UserDict[common.Mssql] {
		for _, password := range common.Passwords {
			if err := mssqlLogin(hostInfo.IP, hostInfo.Port, username, password); err == nil {
				now := time.Now()
				vulInfo := common.Vul{
					CreateTime:  now,
					VulLevel:    common.HighLevel,
					VulName:     common.MssqlWeakPass,
					VulType:     common.WeakPassType,
					Description: common.MssqlWeakPassDescription,
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

func mssqlLogin(ip, port, username, password string) error {
	dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v", ip, username, password, port, time.Duration(common.Timeout)*time.Second)
	db, err := sql.Open("mssql", dataSourceName)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	if err = db.Ping(); err != nil {
		return err
	}
	db.Close()
	return nil
}

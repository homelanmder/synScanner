package plugin

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func MongodbConn(hostInfo *common.HostInfo) {
	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	//优先检测未授权访问
	unauthenticUrl := fmt.Sprintf("mongodb://%s", host)
	if err := connectMongo(unauthenticUrl); err == nil {
		now := time.Now()
		vulInfo := common.Vul{
			CreateTime:     now,
			VulLevel:       common.HighLevel,
			VulName:        common.MongodbUnauthenticatedLogin,
			VulType:        common.WeakPassType,
			Description:    common.MongodbUnauthenticatedDescription,
			Remediation:    common.UnauthenticatedRemediation,
			Host:           host,
			Ip:             hostInfo.IP,
			Port:           hostInfo.Port,
			LatestFindTime: now,
		}
		common.SaveVulInfo(vulInfo)
		fmt.Println(vulInfo)
		return
	} else {
		for _, username := range common.UserDict[common.Mongodb] {
			for _, password := range common.Passwords {
				userPassUrl := fmt.Sprintf("mongodb://%s:%s@%s", username, password, host)
				if e := connectMongo(userPassUrl); e == nil {
					now := time.Now()
					vulInfo := common.Vul{
						CreateTime:  now,
						VulLevel:    common.HighLevel,
						VulName:     common.MongodbWeakPass,
						VulType:     common.WeakPassType,
						Description: common.MongodbWeakPassDescription,
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
}

func connectMongo(connectionString string) error {
	clientOptions := options.Client().ApplyURI(connectionString).SetDirect(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(common.Timeout)*time.Second)
	defer cancel()
	// 创建一个新的MongoDB客户端
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}

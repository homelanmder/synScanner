package scan

import (
	"github.com/homelanmder/synScanner/common"
	"github.com/homelanmder/synScanner/plugin"
)

func WeakScan(hostInfo *common.HostInfo) {
	switch hostInfo.VulType {
	case common.Ftp:
		plugin.FtpConn(hostInfo)
	case common.Ssh:
		plugin.SshConn(hostInfo)
	case common.Telnet:
		plugin.TelnetConn(hostInfo)
	case common.FindNet:
		plugin.FindnetScan(hostInfo)
	case common.Smb:
		plugin.MS17010Scan(hostInfo)
		plugin.SmbConn(hostInfo)
	case common.Rtsp:
		plugin.RtspConn(hostInfo)
	case common.Oracle:
		plugin.OracleConn(hostInfo)
	case common.Mssql:
		plugin.MssqlConn(hostInfo)
	case common.Zookeeper:
		plugin.ZookeeperConn(hostInfo)
	case common.Mysql:
		plugin.MysqlConn(hostInfo)
	case common.Rdp:
		plugin.BlueKeepScan(hostInfo)
		plugin.RdpConn(hostInfo)
	case common.Postgresql:
		plugin.PostgresConn(hostInfo)
	case common.Redis:
		plugin.RedisConn(hostInfo)
	case common.Memcached:
		plugin.MemcachedConn(hostInfo)
	case common.Mongodb:
		plugin.MongodbConn(hostInfo)
	case common.Onvif:
		plugin.OnvifScan(hostInfo)
	default:
		if hostInfo.Finger != "notag" || hostInfo.Finger != "" {
			pocs := common.GetPoc(hostInfo.Finger)
			for _, poc := range pocs {
				plugin.PocScan(poc, hostInfo)
			}
		}
	}
}

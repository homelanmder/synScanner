package common

//解决方案

const (
	AnonymousRemediation       = "禁用匿名登录"
	UnauthenticatedRemediation = "强制认证后访问"
	WeakPassRemediation        = "使用多种字符组合的强密码，如大小写字母+数字+特殊字符"
	MultiIpRemediation         = "删除或禁用多余的网卡"
	Ms17010Remediation         = "1、禁用SMBv1;2、安装MS17-010补丁,补丁链接:https://support.microsoft.com/zh-cn/help/4013389/title"
	BlueKeepRemediation        = "目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：https://portal.msrc.microsoft.com/zh-CN/security-guidance/advisory/CVE-2019-0708"
)

// 问题描述
const (
	FtpAnonymousDescription             = "FTP服务开启了匿名登录，任何人都能登陆FTP服务"
	FtpWeakPassDescription              = "FTP服务使用了弱口令"
	SSHWeakPassDescription              = "SSH服务使用了弱口令"
	TelnetWeakPassDescription           = "Telnet服务使用了弱口令"
	SmbWeakPassDescription              = "SMB服务使用了弱口令"
	MssqlWeakPassDescription            = "Mssql服务使用了弱口令"
	OracleWeakPassDescription           = "Oracle服务使用了弱口令"
	ZookeeperUnauthenticatedDescription = "ZooKeeper是一个高性能的分布式数据一致性解决方案，它将复杂的，容易出错的分布式一致性服务封装起来，构成一个高效可靠的原语集，并提供一系列简单易用的接口给客户使用。ZooKeeper默认开启在2181端口，在未进行任何访问控制情况下，攻击者可通过执行envi命令获得系统大量的敏感信息，包括系统名称、Java环境。"
	MysqlWeakPassDescription            = "Mysql服务使用了弱口令"
	RtspWeakPassDescription             = "Rtsp服务使用了弱口令"
	MemcachedUnauthenticatedDescription = "Memcached服务未使用口令认证，任何人都能登陆Memcached服务"
	MongodbWeakPassDescription          = "Mongodb服务使用了弱口令"
	MongodbUnauthenticatedDescription   = "Mongodb服务未使用口令认证，任何人都能登陆Mongodb服务"
	PostgresqlWeakPassDescription       = "Postgresql服务使用了弱口令"
	RedisWeakPassDescription            = "Redis服务使用了弱口令"
	RedisUnauthenticatedDescription     = "Redis服务未使用口令认证，任何人都能登陆Redis服务"
	MultiIpDescription                  = "同一主机存在多个IP地址"
	RdpWeakPassDescription              = "远程桌面服务使用了弱口令"
	Ms17010Description                  = "Microsoft服务器消息块1.0(SMBv1)服务器处理某些请求的方式存在远程代码执行漏洞,成功利用漏洞的攻击者可以获得在目标服务器上执行代码的能力"
	BlueKeepDescription                 = "Microsoft Windows是美国微软（Microsoft）公司的一套个人设备使用的操作系统。中存在输入验证错误漏洞。该漏洞源于网络系统或产品未对输入的数据进行正确的验证。以下产品及版本受到影响：Winodws XP,Windows Server 2003,Winodws 7,Windows Server 2008"
	OnvifWeakPassDescription            = "Onvif服务使用了弱口令"
	OnvifUnauthenticatedDescription     = "Onvif服务未使用口令认证，任何人都能登陆Onvif服务"
)

// 等级
const (
	Critical      = "Critical"
	High          = "High"
	Medium        = "Medium"
	Low           = "Low"
	CriticalLevel = "严重"
	HighLevel     = "高危"
	MediumLevel   = "中危"
	LowLevel      = "低危"
)

//漏洞类型

const (
	WeakPassType = "pass"
	WebVul       = "web"
	MultiIp      = "multiIp"
)

//rtsp相关

const (
	Digest       = "Digest"
	Basic        = "Basic"
	LoginSuccess = "RTSP/1.0 200 Ok"
)

//漏洞名称

const (
	FtpAnonymousLogin             = "FTP匿名登录"
	FtpWeakPass                   = "FTP弱口令"
	SshWeakPass                   = "SSH弱口令"
	TelnetWeakPass                = "Telnet弱口令"
	MongodbWeakPass               = "Mongodb弱口令"
	MongodbUnauthenticatedLogin   = "Mongodb匿名登录"
	MemcachedUnauthenticatedLogin = "Memcached未授权访问"
	ZookeeperUnauthenticatedLogin = "Zookeeper未授权访问"
	MssqlWeakPass                 = "Mssql弱口令"
	MysqlWeakPass                 = "Mysql弱口令"
	RtspWeakPass                  = "Rtsp弱口令"
	RtspUnauthenticatedLogin      = "Rtsp未授权访问"
	OracleWeakPass                = "Oracle弱口令"
	PostgresqlWeakPass            = "Postgresql弱口令"
	RedisWeakPass                 = "Redis弱口令"
	RedisUnauthenticatedLogin     = "Redis未授权访问"
	SmbWeakPass                   = "SMB弱口令"
	MultiIpVul                    = "多穴主机"
	RdpWeakPass                   = "远程桌面弱口令"
	Ms17010                       = "MS17-010"
	BlueKeep                      = "CVE-2019-0708"
	OnvifWeakPass                 = "Onvif弱口令"
	OnvifUnauthenticatedLogin     = "Onvif未授权访问"
)

// 数据库名称
const (
	RuleDb             = "rules"
	VulDb              = "vul"
	PocDb              = "poc"
	AssetDb            = "assets"
	TaskDb             = "task"
	TaskCollection     = "taskCollection"
	ResponseCollection = "responseCollection"
	IconCollection     = "icoCollection"
	PocCollection      = "pocCollection"
	VulUrl             = "vulUrl"
)

// network
const (
	VulName       = "vulName"
	Ip            = "ip"
	Port          = "port"
	Tcp           = "tcp"
	Web           = "web"
	Headers       = "header"
	Code          = "code"
	Cookie        = "cookie"
	Linux         = "Linux"
	Windows       = "Windows"
	LinuxTTL      = 64
	Ftp           = "ftp"
	Ssh           = "ssh"
	Telnet        = "telnet"
	FindNet       = "msrpc"
	NetBios       = "netBios"
	Smb           = "smb"
	Rtsp          = "rtsp"
	Mssql         = "mssql"
	Oracle        = "oracle"
	Mysql         = "mysql"
	Rdp           = "rdp"
	Zookeeper     = "zookeeper"
	Sip           = "sip"
	Postgresql    = "postgresql"
	Redis         = "redis"
	Memcached     = "memcached"
	Mongodb       = "mongodb"
	Rmi           = "rmi"
	Socks5        = "socks5"
	Vmware        = "vmware"
	Http          = "http"
	Https         = "https"
	Elasticsearch = "elasticsearch"
	Onvif         = "onvif"
	Vnc           = "vnc"
	Rsync         = "rsync"
	ActiveMQ      = "activemq"
	AMQP          = "amqp"
	Docker        = "docker"
	Websocket     = "websocket"
)

//port

const (
	FtpPort           = "21"
	SshPort           = "22"
	TelnetPort        = "23"
	FindNetPort       = "135"
	NetBiosPort       = "139"
	SmbPort           = "445"
	RtspPort          = "554"
	MssqlPort         = "1433"
	OraclePort        = "1521"
	ZookeeperPort     = "2181"
	MysqlPort         = "3306"
	RdpPort           = "3389"
	PostgresqlPort    = "5432"
	SipPort           = "5060"
	RedisPort         = "6379"
	ElasticsearchPort = "9200"
	MemcachedPort     = "11211"
	MongodbPort       = "27017"
)

const (
	Finish    = "finish"
	StatusKey = "status"
)

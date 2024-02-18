package common

import (
	"github.com/homelanmder/synScanner/pkg/protocols/common/protocolstate"
	"github.com/valyala/fasthttp"
	"net"
	"regexp"
	"time"
)

var (
	DefaultPort = "80,443,554,8000,8443,37777,49152,21,22,23,26,37,49,70,79,81,82,83,84,88,102,104,111,113,119,135,138,139,16080,175,179,199,264,389,391,444,445,465,502,503,512,515,523,548,636,705,771,789,873,880,902,992,993,995,1025,1026,1027,1080,1099,1200,1234,1311,1344,1433,1471,1521,1604,1645,1863,1883,1911,1967,1991,1993,2000,2001,2004,2080,2082,2083,2087,2094,2121,2181,2222,2323,2332,2375,2376,2379,2401,2404,2424,2425,2427,2455,2501,3000,3001,3128,3260,3288,3299,3306,3307,3310,3333,3388,3389,3390,3541,3542,3671,3689,3749,3780,3784,4000,4022,4040,4070,4443,4444,4567,4712,4730,4786,4800,4848,4880,4911,4949,5000,5001,5006,5007,5009,5050,5060,5094,5222,5269,5357,5400,5432,5554,5555,5560,5577,5632,5672,5678,5683,5900,5901,5938,5984,5985,5986,6000,6001,6379,6488,6633,6664,6665,6666,6667,6668,6669,6881,6969,7000,7001,7071,7077,7288,7474,7547,7548,7634,7777,7779,7911,8001,8008,8009,8010,8060,8069,8080,8081,8082,8086,8087,8088,8089,8090,8098,8099,8112,8139,8161,8200,8291,8333,8334,8377,8378,8383,8545,8554,8585,8649,8686,8800,8834,8880,8888,8889,9000,9003,9010,9042,9051,9080,9100,9151,9191,9200,9333,9418,9443,9595,9600,9653,9700,9711,9944,9981,9999,10000,10162,10243,10333,11001,11211,11300,11310,12345,13579,14000,30080,14147,14265,16010,16992,16993,18081,20000,20547,20574,22105,22222,23023,23424,25105,25565,27015,27017,28017,28784,30310,30311,30312,30313,30718,32400,32768,33338,34567,34962,34963,34964,35669,42777,44818,45554,47808,49151,49153,49154,49155,50000,50070,50100,51106,55553,59110,61593,61613,61616,62078,62110,64738"
	UserDict    = map[string][]string{
		"ftp":        {"ftp", "admin", "root"},
		"mysql":      {"root", "mysql"},
		"mssql":      {"sa", "sql"},
		"smb":        {"administrator", "admin", "guest"},
		"rdp":        {"administrator", "admin", "guest"},
		"postgresql": {"postgres", "admin"},
		"ssh":        {"root", "admin"},
		"mongodb":    {"root", "admin", ""},
		"oracle":     {"sys", "system", "admin", "orcl"},
		"onvif":      {"admin"},
	}
	Passwords              = []string{"admin123", "123456", "admin", "root", "111111"}
	UserAgent              = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
	Accept                 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
	TaskName               string
	Timeout                int
	Thread                 int
	LocalPort              int
	InteractIp             string
	HttpClient             *fasthttp.Client
	FastDialer, _          = protocolstate.GetDialer()
	LocalIp                string
	ErrRegex, _            = regexp.Compile(`contents: "[^"]*"`)
	InterfaceName          string
	SshMatchProtocol       = MatchProtocol{Match: SshProtocol, Value: Ssh, VulType: Ssh}
	MysqlMatchProtocol     = MatchProtocol{Match: MysqlProtocol, Value: Mysql, VulType: Mysql}
	VmwareMatchProtocol    = MatchProtocol{Match: VmwareProtocol, Value: Vmware}
	PostgresMatchProtocol  = MatchProtocol{Match: PostgresProtocol, Value: Postgresql, VulType: Postgresql}
	RmiMatchProtocol       = MatchProtocol{Match: RmiProtocol, Value: Rmi}
	OracleMatchProtocol    = MatchProtocol{Match: OracleProtocol, Value: Oracle, VulType: Oracle}
	Socks5MatchProtocol    = MatchProtocol{Match: Socks5Protocol, Value: Socks5}
	MssqlMatchProtocol     = MatchProtocol{Match: MssqlProtocol, Value: Mssql, VulType: Mssql}
	MemcachedMatchProtocol = MatchProtocol{Match: MemcachedProtocol, Value: Memcached, VulType: Memcached}
	RedisMatchProtocol     = MatchProtocol{Match: RedisProtocol, Value: Redis, VulType: Redis}
	RtspMatchProtocol      = MatchProtocol{Match: RtspProtocol, Value: Rtsp, VulType: Rtsp}
	HttpMatchProtocol      = MatchProtocol{Match: HttpProtocol, Value: Http}
	HttpsMatchProtocol     = MatchProtocol{Match: HttpsProtocol, Value: Https}
	ZookeeperMatchProtocol = MatchProtocol{Match: ZookeeperProtocol, Value: Zookeeper, VulType: Zookeeper}
	MongodbMatchProtocol   = MatchProtocol{Match: MongodbProtocol, Value: Mongodb, VulType: Mongodb}
	OnvifMatchProtocol     = MatchProtocol{Match: OnvifProtocol, Value: Onvif, VulType: Onvif}
	ActiveMQMatchProtocol  = MatchProtocol{Match: ActiveMQProtocol, Value: ActiveMQ, VulType: ActiveMQ}
	AMQPMatchProtocol      = MatchProtocol{Match: AMQPProtocol, Value: AMQP, VulType: AMQP}
	VncMatchProtocol       = MatchProtocol{Match: VncProtocol, Value: Vnc, VulType: Vnc}
	RsyncMatchProtocol     = MatchProtocol{Match: RsyncProtocol, Value: Rsync, VulType: Rsync}
	DockerMatchProtocol    = MatchProtocol{Match: DockerProtocol, Value: Docker, VulType: Docker}
	WebSocketMatchProtocol = MatchProtocol{Match: WebSocketProtocol, Value: Websocket, VulType: Websocket}
	Probes                 = []string{HttpsProbe, RtspProbe, RmiProbe, PostgresProbe, OracleProbe, Socks5Probe, MssqlProbe, MemcachedProbe, RedisProbe, MongodbProbe}
	MatchProtocols         = []MatchProtocol{OnvifMatchProtocol, HttpMatchProtocol, HttpsMatchProtocol, RtspMatchProtocol, ZookeeperMatchProtocol, SshMatchProtocol, MysqlMatchProtocol, VmwareMatchProtocol, MongodbMatchProtocol, PostgresMatchProtocol, OracleMatchProtocol, MssqlMatchProtocol, RedisMatchProtocol, MemcachedMatchProtocol, RmiMatchProtocol, Socks5MatchProtocol, ActiveMQMatchProtocol, AMQPMatchProtocol, VncMatchProtocol, RsyncMatchProtocol}
	ErrMatchProtocols      = []MatchProtocol{RtspMatchProtocol, ZookeeperMatchProtocol, DockerMatchProtocol, WebSocketMatchProtocol, SshMatchProtocol, MysqlMatchProtocol, VmwareMatchProtocol, ActiveMQMatchProtocol, AMQPMatchProtocol, VncMatchProtocol, RsyncMatchProtocol}
)

type MatchProtocol struct {
	Match   string
	Value   string
	VulType string
}

type UserPassDict struct {
	UserName string
	PassWord string
}

type HostInfo struct {
	IP       string
	Port     string
	Tag      string
	Name     string
	Finger   string
	Type     string
	Url      string
	WebTitle string
	Os       string
	VulType  string
}

type RuleData struct {
	Name  string `json:"name" bson:"name"`
	Value string `json:"value" bson:"value"`
	Class string `json:"class" bson:"class"`
	Type  string `json:"type" bson:"type"`
	Rule  string `json:"rule" bson:"rule"`
}

type Mh3Data struct {
	Name  string `json:"name" bson:"name"`
	Value string `json:"value" bson:"value"`
	Class string `json:"class" bson:"class"`
	Mmh3  string `json:"mmh3" bson:"mmh3"`
}

type Vul struct {
	CreateTime     time.Time    `json:"createTime" bson:"createTime"`
	VulName        string       `json:"vulName" bson:"vulName"`
	VulUrl         string       `json:"vulUrl" bson:"vulUrl"`
	Host           string       `json:"host" bson:"host"`
	Ip             string       `json:"ip" bson:"ip"`
	Port           string       `json:"port" bson:"port"`
	VulLevel       string       `json:"vulLevel" bson:"vulLevel"`
	VulType        string       `json:"vulType" bson:"vulType"`
	Description    string       `json:"description" bson:"description"`
	Remediation    string       `json:"remediation" bson:"remediation"`
	WeakPass       UserPassDict `json:"weakPass" bson:"weakPass"`
	Ips            string       `json:"ips" bson:"ips"`
	LatestFindTime time.Time    `json:"latestFindTime" bson:"latestFindTime"`
}

type Poc struct {
	Tag  []string `json:"tag" bson:"tag"`
	Data []byte   `json:"data" bson:"data"`
}

type Asset struct {
	Time           time.Time `json:"time" bson:"time"`
	Ip             string    `json:"ip" bson:"ip"`
	Port           string    `json:"port" bson:"port"`
	Name           string    `json:"name" bson:"name"`
	Finger         string    `json:"finger" bson:"finger"`
	Type           string    `json:"type" bson:"type"`
	OS             string    `json:"os" bson:"os"`
	WebTitle       string    `json:"webTitle" bson:"webTitle"`
	Url            string    `json:"url" bson:"url"`
	IsNew          bool      `json:"isNew" bson:"isNew"`
	LatestFindTime time.Time `json:"latestFindTime" bson:"latestFindTime"`
}

type Payload struct {
	TaskName    string `json:"taskName"`
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	Name        string `json:"name"`
	Url         string `json:"url"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

func init() {
	LocalIp = getLocalIp()
}
func getLocalIp() (localIp string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return localIp
	}

	// 遍历网络接口
	for _, iface := range interfaces {
		if iface.Name == InterfaceName {
			// 获取网络接口的地址信息
			addrs, err := iface.Addrs()
			if err != nil {
				return localIp
			}
			// 遍历地址信息，找到IPv4或IPv6地址
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if ok && !ipnet.IP.IsLoopback() {
					return ipnet.IP.String()
				}
			}
		}
	}
	return localIp
}

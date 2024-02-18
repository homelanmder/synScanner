package scan

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"github.com/twmb/murmur3"
	"github.com/use-go/onvif/device"
	"github.com/valyala/fasthttp"
	"github.com/homelanmder/synScanner/common"
	"net"
	"regexp"
	"strings"
	"time"
)

func SetHostInfo(hostInfo *common.HostInfo) {
	switch hostInfo.Port {
	case common.FtpPort:
		hostInfo.VulType = common.Ftp
		hostInfo.Finger = common.Ftp
	case common.SshPort:
		hostInfo.VulType = common.Ssh
		hostInfo.Finger = common.Ssh
	case common.TelnetPort:
		hostInfo.VulType = common.Telnet
		hostInfo.Finger = common.Telnet
	case common.FindNetPort:
		hostInfo.VulType = common.FindNet
		hostInfo.Finger = common.FindNet
	case common.NetBiosPort:
		hostInfo.Finger = common.NetBios
	case common.SmbPort:
		hostInfo.VulType = common.Smb
		hostInfo.Finger = common.Smb
	case common.RtspPort:
		hostInfo.VulType = common.Rtsp
		hostInfo.Finger = common.Rtsp
	case common.MssqlPort:
		hostInfo.VulType = common.Mssql
		hostInfo.Finger = common.Mssql
	case common.OraclePort:
		hostInfo.VulType = common.Oracle
		hostInfo.Finger = common.Oracle
	case common.ZookeeperPort:
		hostInfo.VulType = common.Zookeeper
		hostInfo.Finger = common.Zookeeper
	case common.MysqlPort:
		hostInfo.VulType = common.Mysql
		hostInfo.Finger = common.Mysql
	case common.RdpPort:
		hostInfo.VulType = common.Rdp
		hostInfo.Finger = common.Rdp
	case common.PostgresqlPort:
		hostInfo.VulType = common.Postgresql
		hostInfo.Finger = common.Postgresql
	case common.SipPort:
		hostInfo.Finger = common.Sip
	case common.RedisPort:
		hostInfo.VulType = common.Redis
		hostInfo.Finger = common.Redis

	case common.ElasticsearchPort:
		hostInfo.Finger = common.Elasticsearch
		hostInfo.Tag = common.Web
		hostInfo.Url = fmt.Sprintf("http://%s:%s", hostInfo.IP, hostInfo.Port)
	case common.MemcachedPort:
		hostInfo.VulType = common.Memcached
		hostInfo.Finger = common.Memcached
	case common.MongodbPort:
		hostInfo.VulType = common.Mongodb
		hostInfo.Finger = common.Mongodb
	default:
		distinguishProtocol(hostInfo)
	}
	fmt.Println("协议识别结束")
	//http指纹识别
	if hostInfo.Finger == "" && hostInfo.Tag == common.Web {
		sendHttp(hostInfo)
	}

	//入库
	now := time.Now()
	asset := common.Asset{
		Time:           now,
		Ip:             hostInfo.IP,
		Port:           hostInfo.Port,
		Finger:         hostInfo.Finger,
		Type:           hostInfo.Type,
		Name:           hostInfo.Name,
		OS:             hostInfo.Os,
		WebTitle:       hostInfo.WebTitle,
		Url:            hostInfo.Url,
		IsNew:          true,
		LatestFindTime: now,
	}
	common.SaveAsset(asset)
	fmt.Println(asset)
	//开始漏洞扫描
	WeakScan(hostInfo)
}

func sendHttp(hostInfo *common.HostInfo) {
	var err error
	var icon string
	var body string
	var header string
	var req *fasthttp.Request
	var resp *fasthttp.Response
	req = fasthttp.AcquireRequest()
	resp = fasthttp.AcquireResponse()
	req.SetConnectionClose()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	req.SetRequestURI(hostInfo.Url)
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set("User-Agent", common.UserAgent)
	req.Header.Set("Accept", common.Accept)
	if err = common.HttpClient.DoRedirects(req, resp, 3); err != nil {
		fmt.Println(hostInfo.IP, hostInfo.Port, err.Error())
		return
	}

	body = string(resp.Body())
	hostInfo.WebTitle = getTile(body)
	header = resp.Header.String()
	cookie := string(resp.Header.Peek("Set-Cookie"))

	//获取ico
	req.SetRequestURI(hostInfo.Url + "/favicon.ico")
	if err = common.HttpClient.DoRedirects(req, resp, 3); err != nil {
		fmt.Println(hostInfo.IP, hostInfo.Port, err.Error())
		return
	}
	if resp.StatusCode() == fasthttp.StatusOK {
		icon = calculateIcoHash(resp.Body())
	}

	hostInfo.Name, hostInfo.Finger, hostInfo.Type = matchProduct(header, body, cookie, icon)
}

func getTile(body string) string {
	titleRegex, _ := regexp.Compile("<title>.*</title>")
	title := titleRegex.FindString(body)
	title = strings.TrimPrefix(title, "<title>")
	title = strings.TrimSuffix(title, "</title>")
	return title
}

func matchProduct(header, body, cookie, icon string) (name, finger, appType string) {

	for _, rule := range common.ResponseRule {
		var ok bool
		switch rule.Type {
		case common.Headers:
			ok, _ = regexp.MatchString(rule.Rule, header)
		case common.Code:
			ok, _ = regexp.MatchString(rule.Rule, body)
		case common.Cookie:
			ok, _ = regexp.MatchString(rule.Rule, cookie)
		}
		if ok {
			return rule.Name, rule.Value, rule.Class
		}
	}
	for _, rule := range common.IcoRule {

		if rule.Mmh3 == icon {
			return rule.Name, rule.Value, rule.Class
		}
	}
	return name, finger, appType
}

func calculateIcoHash(data []byte) string {
	bckd := base64.StdEncoding.EncodeToString(data)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	r := murmur3.New32()
	r.Write(buffer.Bytes())
	return fmt.Sprintf("%d", int32(r.Sum32()))
}

// 协议识别
func distinguishProtocol(hostInfo *common.HostInfo) {

	//首先发送一个http请求,优先匹配onvif
	sendOnvif(hostInfo)
	if hostInfo.VulType != "" || hostInfo.Tag != "" {
		return
	}
	for _, probe := range common.Probes {
		sendProbe(hostInfo, probe)
		//匹配成功,直接返回
		if hostInfo.Finger != "" || hostInfo.Tag != "" {
			return
		}
	}

}

func sendProbe(hostInfo *common.HostInfo, probe string) {
	conn, err := net.DialTimeout(common.Tcp, fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port), time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return
	}
	conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	d, _ := hex.DecodeString(probe)
	if _, err = conn.Write(d); err != nil {
		return
	}

	data := make([]byte, 128)
	length, err := conn.Read(data)
	if err != nil {
		return
	}
	conn.Close()
	rec := hex.EncodeToString(data[:length])
	value, vulType, ok := matchProtocol(rec, common.MatchProtocols)
	if ok {
		switch value {
		case common.Http:
			hostInfo.Tag = common.Web
			hostInfo.Url = fmt.Sprintf("http://%s:%s", hostInfo.IP, hostInfo.Port)
		case common.Https:
			hostInfo.Tag = common.Web
			hostInfo.Url = fmt.Sprintf("https://%s:%s", hostInfo.IP, hostInfo.Port)
		default:
			hostInfo.Finger = value
			hostInfo.VulType = vulType
		}
	}
}

func sendOnvif(hostInfo *common.HostInfo) {
	var err error
	u := fmt.Sprintf("http://%s:%s/onvif/device_service", hostInfo.IP, hostInfo.Port)
	req := fasthttp.AcquireRequest()
	req.Header.Set("User-Agent", common.UserAgent)
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.SetRequestURI(u)
	req.SetBodyRaw([]byte(common.HttpProbe))
	req.Header.SetMethod(fasthttp.MethodPost)
	req.SetConnectionClose()
	resp := fasthttp.AcquireResponse()
	if err = common.HttpClient.Do(req, resp); err != nil {
		fmt.Println(err.Error())
		content := common.ErrRegex.FindString(err.Error())
		value, vulType, ok := matchProtocol(hex.EncodeToString([]byte(content)), common.ErrMatchProtocols)
		if ok {
			hostInfo.Finger = value
			hostInfo.VulType = vulType
		}
		return
	}

	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	hostInfo.Tag = common.Web
	hostInfo.Url = fmt.Sprintf("http://%s:%s", hostInfo.IP, hostInfo.Port)
	value, _, ok := matchProtocol(hex.EncodeToString(resp.Body()), common.MatchProtocols)
	if ok {
		switch value {
		case common.Onvif:
			hostInfo.VulType = common.Onvif
			//标注onvif,后续对设备进行厂商识别,并且还要扫描厂商漏洞
		}
		//未授权,后续不爆破
		if resp.StatusCode() == fasthttp.StatusOK {
			type Envelope struct {
				Header struct{}
				Body   struct {
					GetDeviceInformationResponse device.GetDeviceInformationResponse
				}
			}
			var reply Envelope
			if err = xml.Unmarshal(resp.Body(), &reply); err != nil {
				return
			}
			if reply.Body.GetDeviceInformationResponse.HardwareId == "" {
				return
			}
			//后续未授权不用爆破
			hostInfo.VulType = common.OnvifUnauthenticatedLogin
			now := time.Now()
			vul := common.Vul{
				CreateTime:     now,
				VulName:        common.OnvifUnauthenticatedLogin,
				Host:           fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port),
				VulLevel:       common.HighLevel,
				Ip:             hostInfo.IP,
				Port:           hostInfo.Port,
				VulType:        common.WeakPassType,
				Description:    common.OnvifUnauthenticatedDescription,
				Remediation:    common.UnauthenticatedRemediation,
				LatestFindTime: now,
			}
			common.SaveVulInfo(vul)
			fmt.Println(vul)
		}
	} else if strings.Contains(string(resp.Body()), "400 The plain HTTP request was sent to HTTPS port") && resp.StatusCode() == fasthttp.StatusBadRequest {
		{
			hostInfo.Tag = common.Web
			hostInfo.Url = fmt.Sprintf("https://%s:%s", hostInfo.IP, hostInfo.Port)
		}
	}
}

func matchProtocol(rec string, matchProtocols []common.MatchProtocol) (string, string, bool) {
	for _, p := range matchProtocols {
		re, _ := regexp.Compile(p.Match)
		if re.MatchString(rec) {
			return p.Value, p.VulType, true
		}
	}
	return "", "", false
}

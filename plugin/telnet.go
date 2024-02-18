package plugin

import (
	"fmt"
	"github.com/homelanmder/synScanner/common"

	"log"
	"net"

	"strings"
	"time"
)

type TelnetClient struct {
	IP               string
	Port             string
	IsAuthentication bool
	UserName         string
	Password         string
}

func TelnetConn(hostInfo *common.HostInfo) {
	for _, username := range common.UserDict[common.Telnet] {
		for _, password := range common.Passwords {
			if success, _ := telnetLogin(hostInfo.IP, hostInfo.Port, username, password); success {
				now := time.Now()
				vulInfo := common.Vul{
					CreateTime:  now,
					VulLevel:    common.HighLevel,
					VulName:     common.TelnetWeakPass,
					VulType:     common.WeakPassType,
					Description: common.TelnetWeakPassDescription,
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

func telnetLogin(ip, port, username, password string) (bool, error) {
	telnetClientObj := new(TelnetClient)
	telnetClientObj.IP = ip
	telnetClientObj.Port = port
	telnetClientObj.IsAuthentication = true
	telnetClientObj.UserName = username
	telnetClientObj.Password = password
	ret, err := telnetClientObj.Telnet(common.Timeout)
	if err != nil {
		return false, err
	}
	return ret, nil
}

func (this *TelnetClient) Telnet(timeout int) (bool, error) {
	raddr := this.IP + ":" + this.Port
	conn, err := net.DialTimeout("tcp", raddr, time.Duration(timeout)*time.Second)
	if nil != err {
		log.Print("pkg: model, func: Telnet, method: net.DialTimeout, errInfo:", err)
		return false, err
	}
	defer conn.Close()
	if false == this.telnetProtocolHandshake(conn) {
		//log.Print("pkg: model, func: Telnet, method: this.telnetProtocolHandshake, errInfo: telnet protocol handshake failed!!!")
		return false, err
	}
	return true, err
}

func (this *TelnetClient) telnetProtocolHandshake(conn net.Conn) bool {
	var buf [4096]byte
	var n int
	n, err := conn.Read(buf[0:])
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake1, method: conn.Read, errInfo:", err)
		return false
	}

	buf[0] = 0xff
	buf[1] = 0xfc
	buf[2] = 0x25
	buf[3] = 0xff
	buf[4] = 0xfe
	buf[5] = 0x01
	n, err = conn.Write(buf[0:6])
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake2, method: conn.Write, errInfo:", err)
		return false
	}

	n, err = conn.Read(buf[0:])
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake3, method: conn.Read, errInfo:", err)
		return false
	}

	buf[0] = 0xff
	buf[1] = 0xfe
	buf[2] = 0x03
	buf[3] = 0xff
	buf[4] = 0xfc
	buf[5] = 0x27
	n, err = conn.Write(buf[0:6])
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake4, method: conn.Write, errInfo:", err)
		return false
	}

	n, err = conn.Read(buf[0:])
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake5, method: conn.Read, errInfo:", err)
		return false
	}

	//fmt.Println((buf[0:n]))
	n, err = conn.Write([]byte(this.UserName + "\r\n"))
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake6, method: conn.Write, errInfo:", err)
		return false
	}
	time.Sleep(time.Millisecond * 500)

	n, err = conn.Read(buf[0:])
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake7, method: conn.Read, errInfo:", err)
		return false
	}

	n, err = conn.Write([]byte(this.Password + "\r\n"))
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake8, method: conn.Write, errInfo:", err)
		return false
	}
	time.Sleep(time.Millisecond * 2000)
	n, err = conn.Read(buf[0:])
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake9, method: conn.Read, errInfo:", err)
		return false
	}
	if strings.Contains(string(buf[0:n]), "Login Failed") {
		return false
	}

	buf[0] = 0xff
	buf[1] = 0xfc
	buf[2] = 0x18

	n, err = conn.Write(buf[0:3])
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake6, method: conn.Write, errInfo:", err)
		return false
	}
	n, err = conn.Read(buf[0:])
	if nil != err {
		log.Print("pkg: model, func: telnetProtocolHandshake7, method: conn.Read, errInfo:", err)
		return false
	}
	return true
}

package plugin

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	ldap "github.com/lor00x/goldap/message"
	"github.com/homelanmder/synScanner/common"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	ldapRequest  = "300c020101600702010304008000"
	ldapResponse = "300c02010161070a010004000400"
	httpRequest  = "48545450"
	httpProtocol = 1
	ldapProtocol = 0
)

func Run() {
	listener, err := net.Listen(common.Tcp, fmt.Sprintf("%s:%d", common.LocalIp, common.LocalPort))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		go handler(conn)
	}
}

func handler(conn net.Conn) {
	var length int
	var err error
	data := make([]byte, 1024)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if length, err = conn.Read(data); err != nil {
		return
	}
	requestType := getRequestType(data[:length])
	switch requestType {
	case ldapProtocol:
		processLdap(conn)
	case httpProtocol:
		processHttp(conn, data[:length])
	}

}

func getRequestType(data []byte) int {
	ldapRe, _ := regexp.Compile(ldapRequest)
	httpRe, _ := regexp.Compile(httpRequest)

	if ldapRe.MatchString(hex.EncodeToString(data)) {
		return ldapProtocol
	} else if httpRe.MatchString(hex.EncodeToString(data)) {
		return httpProtocol
	}
	return 3
}

func processLdap(conn net.Conn) {
	defer conn.Close()
	var length int
	var err error
	data := make([]byte, 1024)
	writeData, _ := hex.DecodeString(ldapResponse)
	conn.Write(writeData)
	if length, err = conn.Read(data); err != nil {
		return
	}
	msg, err := ldap.ReadLDAPMessage(ldap.NewBytes(0, data[:length]))
	if err != nil {
		return
	}
	protocolOp := msg.ProtocolOp()
	searchRequest := protocolOp.(ldap.SearchRequest)
	b, err := base64.StdEncoding.DecodeString(string(searchRequest.BaseObject()))
	if err != nil {
		return
	}
	var p common.Payload
	err = json.Unmarshal(b, &p)
	if err != nil {
		return
	}
	if p.TaskName != common.TaskName {
		return
	}
	now := time.Now()
	vul := common.Vul{
		CreateTime:     now,
		VulName:        p.Name,
		VulUrl:         p.Url,
		Ip:             p.Ip,
		Port:           p.Port,
		VulType:        common.WebVul,
		VulLevel:       common.HighLevel,
		Description:    p.Description,
		Remediation:    p.Remediation,
		LatestFindTime: now,
	}
	fmt.Println(vul)
	common.SaveVulInfo(vul)
}

func processHttp(conn net.Conn, data []byte) {
	defer conn.Close()
	reader := bufio.NewReader(bytes.NewReader(data))
	requestLine, _ := reader.ReadString('\n')
	requestLine = strings.TrimSpace(requestLine)

	// 解析请求行
	parts := strings.Split(requestLine, " ")
	if len(parts) != 3 {
		return
	}
	payload := strings.TrimPrefix(parts[1], "/")
	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return
	}
	var p common.Payload
	err = json.Unmarshal(b, &p)
	if err != nil {
		return
	}
	if p.TaskName != common.TaskName {
		return
	}
	now := time.Now()
	vul := common.Vul{
		CreateTime:     now,
		VulName:        p.Name,
		VulUrl:         p.Url,
		Ip:             p.Ip,
		Port:           p.Port,
		VulType:        common.WebVul,
		VulLevel:       common.HighLevel,
		Description:    p.Description,
		Remediation:    p.Remediation,
		LatestFindTime: now,
	}
	common.SaveVulInfo(vul)
}

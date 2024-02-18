package plugin

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"github.com/homelanmder/synScanner/common"

	"strings"
	"time"
)

var (
	bufferV1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	bufferV2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	bufferV3, _ = hex.DecodeString("0900ffff0000")
)

func FindnetScan(hostInfo *common.HostInfo) {
	realhost := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	conn, err := net.DialTimeout(common.Tcp, realhost, time.Duration(common.Timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {

		return
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	if err != nil {

		return
	}
	_, err = conn.Write(bufferV1)
	if err != nil {

		return
	}
	reply := make([]byte, 4096)
	_, err = conn.Read(reply)
	if err != nil {

		return
	}
	_, err = conn.Write(bufferV2)
	if err != nil {

		return
	}
	if n, err := conn.Read(reply); err != nil || n < 42 {

		return
	}
	text := reply[42:]
	flag := true
	for i := 0; i < len(text)-5; i++ {
		if bytes.Equal(text[i:i+6], bufferV3) {
			text = text[:i-4]
			flag = false
			break
		}
	}
	if flag {
		return
	}
	hosts, err := read(text)
	if len(hosts) > 1 {
		now := time.Now()
		vulInfo := common.Vul{
			CreateTime:     now,
			VulLevel:       common.HighLevel,
			VulName:        common.MultiIpVul,
			VulType:        common.MultiIp,
			Description:    common.MultiIpDescription,
			Remediation:    common.MultiIpRemediation,
			Host:           hostInfo.IP,
			Ip:             hostInfo.IP,
			Port:           hostInfo.Port,
			Ips:            strings.Join(hosts, ","),
			LatestFindTime: now,
		}
		common.SaveVulInfo(vulInfo)
	}
}
func read(text []byte) (hosts []string, err error) {
	encodedStr := hex.EncodeToString(text)
	hostnames := strings.Replace(encodedStr, "0700", "", -1)
	hosts = strings.Split(hostnames, "000000")
	for i := 1; i < len(hosts); i++ {
		hosts[i] = strings.Replace(hosts[i], "00", "", -1)
		data, err := hex.DecodeString(hosts[i])
		if err != nil {
			return hosts, err
		}
		hosts[i] = string(data)
	}
	return hosts, nil
}

package plugin

import (
	"fmt"
	"github.com/homelanmder/synScanner/common"
	"net"
	"time"
)

func BlueKeepScan(hostInfo *common.HostInfo) {
	var err error
	var length int
	requestPayload := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT Header
		0x0e, 0xe0, 0x00, 0x00, // X.224 Class 0 Connection Request Header
		0x03, 0x00, 0x00, 0x08, // RDP Negotiation Request Header
		0x03, 0x00, 0x00, 0x01, // RDP Negotiation Request
		0x00, 0x08, // RDP Negotiation Request: Requested Protocols (SSL security)
		0x00, 0x00, 0x00, 0x00, // RDP Negotiation Request: Reserved
		0x00, 0x00, 0x00, 0x00, // RDP Negotiation Request: Reserved
	}
	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	conn, err := net.DialTimeout(common.Tcp, host, time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return
	}
	conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	if _, err = conn.Write(requestPayload); err != nil {
		return
	}
	data := make([]byte, 128)
	if length, err = conn.Read(data); err != nil {
		return
	}
	if length > 3 && data[0] == 0x03 && data[1] == 0x00 && data[2] == 0x00 {
		now := time.Now()
		vul := common.Vul{
			CreateTime:     now,
			VulName:        common.BlueKeep,
			Host:           host,
			Ip:             hostInfo.IP,
			Port:           hostInfo.Port,
			VulLevel:       common.HighLevel,
			VulType:        common.WeakPassType,
			Description:    common.BlueKeepDescription,
			Remediation:    common.BlueKeepRemediation,
			LatestFindTime: now,
		}
		common.SaveVulInfo(vul)
	}
}

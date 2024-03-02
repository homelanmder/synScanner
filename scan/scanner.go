package scan

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/homelanmder/synScanner/common"
	"github.com/mdlayher/arp"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SynScanner struct {
	Handle     *pcap.Handle
	LocalMac   net.HardwareAddr
	LocalIp    net.IP
	GatewayMac net.HardwareAddr
	Channel    chan *common.HostInfo
	Wg         *sync.WaitGroup
}

func Scan(ips, ports string) {
	var allIp []string
	var allPorts []int
	var err error
	var route routing.Router
	var ifs *net.Interface
	var gateway net.IP
	var src net.IP
	var gatewayAddr netip.Addr
	var c *arp.Client

	scanner := SynScanner{
		Wg: new(sync.WaitGroup),
	}

	if route, err = routing.New(); err != nil {
		fmt.Println(err.Error())
		return
	}
	if ifs, gateway, src, err = route.Route(net.ParseIP("8.8.8.8")); err != nil {
		fmt.Println(err.Error())
		return
	}
	scanner.LocalIp = src
	scanner.LocalMac = ifs.HardwareAddr
	if gatewayAddr, err = netip.ParseAddr(gateway.String()); err != nil {
		fmt.Println(err.Error())
		return
	}
	if c, err = arp.Dial(ifs); err != nil {
		fmt.Println(err.Error())
		return
	}
	if scanner.GatewayMac, err = c.Resolve(gatewayAddr); err != nil {
		fmt.Println(err.Error())
		return
	}
	if scanner.Handle, err = pcap.OpenLive(common.InterfaceName, 65536, true, pcap.BlockForever);err!=nil{
		fmt.Println(err.Error())
		return
	}
	if allIp, err = parseIps(ips); err != nil {
		fmt.Println(err.Error())
		return
	}
	if allPorts, err = parsePort(ports); err != nil {
		fmt.Println(err.Error())
		return
	}
	//假设每个ip都有10个端口开放，避免往channel发送数据时，解包阻塞导致丢包
	scanner.Channel = make(chan *common.HostInfo, len(allIp)*10)
	go scanner.DecodePacket()
	for i := 0; i < common.Thread; i++ {
		go func() {
			for hostInfo := range scanner.Channel {
				SetHostInfo(hostInfo)
				scanner.Wg.Done()
			}
		}()
	}
	for _, ip := range allIp {
		for _, port := range allPorts {
			scanner.SendSyn(ip, port)
		}
	}
	time.Sleep(5 * time.Second)
	scanner.Wg.Wait()
	scanner.Handle.Close()
	close(scanner.Channel)
	common.UpdateTaskInfo(common.TaskName, common.StatusKey, common.Finish)
}

func (s *SynScanner) DecodePacket() {
	packetSource := gopacket.NewPacketSource(s.Handle, s.Handle.LinkType())
	var eth layers.Ethernet
	var ipLayer layers.IPv4
	var tcpLayer layers.TCP
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&eth,
			&ipLayer,
			&tcpLayer,
		)

		foundLayerTypes := []gopacket.LayerType{}
		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			continue
		}
		if int(tcpLayer.DstPort) == common.LocalPort && tcpLayer.SYN && tcpLayer.ACK {
			//收到syn
			fmt.Println(ipLayer.SrcIP, tcpLayer.SrcPort, "is open")
			var os string
			if ipLayer.TTL <= common.LinuxTTL {
				os = common.Linux
			} else {
				os = common.Windows
			}
			hostInfo := &common.HostInfo{
				IP:   ipLayer.SrcIP.String(),
				Port: fmt.Sprintf("%d", int(tcpLayer.SrcPort)),
				Os:   os,
			}
			s.Channel <- hostInfo
			s.Wg.Add(1)
		}

	}
}

func (s *SynScanner) SendSyn(dstIp string, dstPort int) {
	eth := layers.Ethernet{
		SrcMAC:       s.LocalMac,
		DstMAC:       s.GatewayMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.LocalIp,
		DstIP:    net.ParseIP(dstIp),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(common.LocalPort),
		DstPort: layers.TCPPort(dstPort), // will trough ports slice
		SYN:     true,
		Window:  29200,
		Seq:     uint32(randSeq()),
		Options: []layers.TCPOption{
			layers.TCPOption{layers.TCPOptionKindMSS, 4, []byte("\x05\xb4")},
			layers.TCPOption{layers.TCPOptionKindSACKPermitted, 2, nil},
			layers.TCPOption{layers.TCPOptionKindNop, 1, nil},
			layers.TCPOption{layers.TCPOptionKindWindowScale, 3, []byte("\x07")},
		},
	}
	tcp.SetNetworkLayerForChecksum(&ip4)
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, opts, &eth, &ip4, &tcp)
	s.Handle.WritePacketData(buffer.Bytes())
}

func randSeq() int {
	seed := rand.NewSource(time.Now().UnixNano())
	return rand.New(seed).Intn(4294967296)
}

func parseIps(inputIp string) ([]string, error) {
	var allIp []string
	info := strings.Split(inputIp, ",")
	for _, inputInfo := range info {
		if strings.Contains(inputInfo, "-") {
			ips, err := convertIPRangeToIPArray(inputInfo)
			if err != nil {
				return nil, err
			}
			allIp = append(allIp, ips...)
		} else if strings.Contains(inputInfo, "/") {
			ips, err := convertIpMaskToIPArray(inputInfo)
			if err != nil {
				return nil, err
			}
			allIp = append(allIp, ips...)
		} else {
			ip, err := singleIp(inputInfo)
			if err != nil {
				return nil, err
			}
			allIp = append(allIp, ip)
		}
	}
	return allIp, nil
}

func convertIpMaskToIPArray(ipCidr string) ([]string, error) {
	ipMask, ipNet, err := net.ParseCIDR(ipCidr)
	if err != nil {

		return nil, err
	}
	startIP := ipMask.Mask(ipNet.Mask)
	endIP := make(net.IP, len(startIP))
	copy(endIP, startIP)
	for i := range endIP {
		endIP[i] |= ^ipNet.Mask[i]
	}
	var ips []string
	for ip := startIP; ip.Equal(endIP) || bytes.Compare(ip, endIP) <= 0; ip = nextIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func singleIp(single string) (string, error) {
	ip := net.ParseIP(single)
	if ip == nil {
		return "", fmt.Errorf("输入的ip不合法")
	}
	return single, nil
}

func convertIPRangeToIPArray(ipRange string) ([]string, error) {
	// 解析IP范围
	startIP, endIP, err := parseIPRange(ipRange)
	if err != nil {
		return nil, err
	}

	// 生成单个IP数组
	var ips []string
	for ip := startIP; ip.Equal(endIP) || bytes.Compare(ip, endIP) <= 0; ip = nextIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

func parseIPRange(ipRange string) (net.IP, net.IP, error) {
	// 分割起始IP和结束IP
	ipRangeParts := strings.Split(ipRange, "-")
	if len(ipRangeParts) != 2 {
		return nil, nil, fmt.Errorf("Invalid IP range format")
	}

	// 解析起始IP
	startIP := net.ParseIP(strings.TrimSpace(ipRangeParts[0]))
	if startIP == nil {
		return nil, nil, fmt.Errorf("Failed to parse start IP")
	}

	// 解析结束IP
	endIP := net.ParseIP(strings.TrimSpace(ipRangeParts[1]))
	if endIP == nil {
		return nil, nil, fmt.Errorf("Failed to parse end IP")
	}

	return startIP, endIP, nil
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)

	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] > 0 {
			break
		}
	}
	return next
}

func parsePort(ports string) ([]int, error) {
	//逗号分割port
	portMap := make(map[int]bool)
	tmp := strings.Split(ports, ",")
	for _, p := range tmp {
		if strings.Contains(p, "-") {
			rangeTmp := strings.Split(p, "-")
			if len(rangeTmp) != 2 {
				return nil, errors.New("格式错误")
			}
			start, err := strconv.Atoi(rangeTmp[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(rangeTmp[1])
			if err != nil {
				return nil, err
			}
			if start > end || start <= 0 || end > 65535 {
				return nil, errors.New("格式错误")
			}
			for i := start; i <= end; i++ {
				portMap[i] = true
			}

		} else {
			port, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			portMap[port] = true
		}
	}
	var portList []int
	for p, _ := range portMap {
		portList = append(portList, p)
	}
	return portList, nil
}

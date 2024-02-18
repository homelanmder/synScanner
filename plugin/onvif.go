package plugin

import (
	"encoding/xml"
	"fmt"
	"github.com/beevik/etree"
	"github.com/use-go/onvif"
	"github.com/use-go/onvif/device"
	"github.com/use-go/onvif/gosoap"
	"github.com/valyala/fasthttp"
	"github.com/homelanmder/synScanner/common"
	"time"
)

func OnvifScan(hostInfo *common.HostInfo) {
	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	for _, username := range common.UserDict[common.Onvif] {
		for _, password := range common.Passwords {

			if err := onvifLogin(host, username, password); err == nil {
				now := time.Now()
				vulInfo := common.Vul{
					CreateTime:  now,
					VulName:     common.OnvifWeakPass,
					VulLevel:    common.HighLevel,
					VulType:     common.WeakPassType,
					Host:        fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port),
					Ip:          hostInfo.IP,
					Port:        hostInfo.Port,
					Description: common.OnvifWeakPassDescription,
					Remediation: common.WeakPassRemediation,
					WeakPass: common.UserPassDict{
						UserName: username,
						PassWord: password,
					},
					LatestFindTime: now,
				}
				fmt.Println(vulInfo)
				common.SaveVulInfo(vulInfo)
				break

			}
		}
	}

}

func onvifLogin(host, username, password string) error {
	var err error
	getDeviceInformation := device.GetDeviceInformation{}
	output, err := xml.MarshalIndent(getDeviceInformation, "  ", "    ")
	if err != nil {
		return err
	}

	doc := etree.NewDocument()
	if err = doc.ReadFromString(string(output)); err != nil {
		return err
	}
	element := doc.Root()
	soap := gosoap.NewEmptySOAP()
	soap.AddBodyContent(element)
	soap.AddRootNamespaces(onvif.Xlmns)
	soap.AddAction()
	soap.AddWSSecurity(username, password)
	req := fasthttp.AcquireRequest()
	req.Header.Set("User-Agent", common.UserAgent)
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.SetRequestURI(fmt.Sprintf("http://%s/onvif/device_service", host))
	req.Header.SetMethod(fasthttp.MethodPost)
	req.SetBodyRaw([]byte(soap.String()))
	resp := fasthttp.AcquireResponse()
	if err = common.HttpClient.Do(req, resp); err != nil {
		fmt.Println(err.Error())
		return err
	}

	defer func() {
		fasthttp.ReleaseResponse(resp)
		fasthttp.ReleaseRequest(req)
	}()

	if resp.StatusCode() != fasthttp.StatusOK {
		return err
	}
	type Envelope struct {
		Header struct{}
		Body   struct {
			GetDeviceInformationResponse device.GetDeviceInformationResponse
		}
	}
	var reply Envelope
	if err = xml.Unmarshal(resp.Body(), &reply); err != nil {
		return err
	}

	if reply.Body.GetDeviceInformationResponse.HardwareId == "" {
		return err
	}
	return err
}

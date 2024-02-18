package plugin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/homelanmder/synScanner/common"
	"github.com/homelanmder/synScanner/internal/runner"
	"github.com/homelanmder/synScanner/pkg/output"
	"github.com/homelanmder/synScanner/pkg/protocols"
	"github.com/homelanmder/synScanner/pkg/protocols/common/contextargs"
	"github.com/homelanmder/synScanner/pkg/protocols/common/utils/excludematchers"
	"github.com/homelanmder/synScanner/pkg/protocols/http/httpclientpool"
	"github.com/homelanmder/synScanner/pkg/templates"
	"github.com/homelanmder/synScanner/pkg/types"
	"github.com/homelanmder/synScanner/pkg/types/scanstrategy"
	"net/url"
	"strings"
)

func PocScan(poc common.Poc, hostInfo *common.HostInfo) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("扫描%s:%s,%v时发生错误,%v", hostInfo.IP, hostInfo.Port, poc.Tag, e)
		}
	}()

	var option = &types.Options{}
	setOpt(option)
	httpclientpool.Init(option, common.FastDialer)
	r, _ := runner.New(option)

	executorOpts := protocols.ExecutorOptions{
		Output:          r.Output,
		Options:         r.Options,
		Progress:        r.Progress,
		RateLimiter:     r.RateLimiter,
		ExcludeMatchers: excludematchers.New(r.Options.ExcludeMatchers),
	}
	if strings.Contains(string(poc.Data), "{{interactsh}}") {
		poc.Data = replaceVar(hostInfo, poc.Data, executorOpts)
	}

	reader := bytes.NewReader(poc.Data)
	template, err := templates.ParseTemplateFromReader(reader, nil, executorOpts)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	for _, req := range template.RequestsHTTP {
		dynamicValues := make(map[string]interface{})
		previous := make(map[string]interface{})
		inputItem := &contextargs.Context{
			MetaInput: &contextargs.MetaInput{Input: hostInfo.Url},
		}
		req.ExecuteWithResults(inputItem, dynamicValues, previous, func(e *output.InternalWrappedEvent) {

			for _, event := range e.Results {
				var vulLevel string
				switch event.Info.SeverityHolder.Severity.String() {
				case common.Critical:
					vulLevel = common.CriticalLevel
				case common.High:
					vulLevel = common.HighLevel
				case common.Medium:
					vulLevel = common.MediumLevel
				case common.Low:
					vulLevel = common.LowLevel
				}
				if event.MatcherStatus {
					vulInfo := common.Vul{
						CreateTime:     event.Timestamp,
						VulLevel:       vulLevel,
						VulName:        event.Info.Name,
						VulUrl:         hostInfo.Url,
						Description:    event.Info.Description,
						Remediation:    event.Info.Remediation,
						LatestFindTime: event.Timestamp,
					}
					if event.Metadata["username"] != nil && event.Metadata["password"] != nil {
						vulInfo.VulType = common.WeakPassType
						var userPass common.UserPassDict
						userPass.UserName = event.Metadata["username"].(string)
						userPass.PassWord = event.Metadata["password"].(string)
						vulInfo.WeakPass = userPass
					} else {
						vulInfo.VulType = common.WebVul
					}
					fmt.Println(vulInfo)
					common.SaveVulInfo(vulInfo)
				}
			}
		})

	}
	r.Close()
}

func setOpt(options *types.Options) {
	options.MaxRedirects = 10
	options.ResponseReadSize = 1024 * 1024
	options.RateLimit = 1
	options.RateLimitMinute = 0
	options.TemplateThreads = 1
	options.Timeout = common.Timeout
	options.Retries = 1
	options.MaxHostError = 1
	options.ScanStrategy = scanstrategy.Auto.String()
	options.PageTimeout = common.Timeout
	options.NoInteractsh = true
	options.NoColor = true
}

func replaceVar(hostInfo *common.HostInfo, data []byte, executorOpts protocols.ExecutorOptions) (finalPayload []byte) {
	reader := bytes.NewReader(data)
	template, err := templates.ParseTemplateFromReader(reader, nil, executorOpts)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	p := common.Payload{
		TaskName:    common.TaskName,
		Ip:          hostInfo.IP,
		Port:        hostInfo.Port,
		Name:        template.Info.Name,
		Description: template.Info.Description,
		Remediation: template.Info.Remediation,
		Url:         hostInfo.Url,
	}
	d, _ := json.Marshal(p)
	payload := strings.ReplaceAll(string(data), "{{interactsh}}", fmt.Sprintf("%s:%d", common.InteractIp, common.LocalPort))
	payload = strings.ReplaceAll(payload, "{{header}}", base64.StdEncoding.EncodeToString(d))
	payload = strings.ReplaceAll(payload, "{{body}}", url.QueryEscape(base64.StdEncoding.EncodeToString(d)))
	payload = strings.ReplaceAll(payload, "{{url}}", url.QueryEscape(base64.StdEncoding.EncodeToString(d)))
	return []byte(payload)
}

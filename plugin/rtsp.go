package plugin

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
	"github.com/homelanmder/synScanner/common"
)

func RtspConn(hostInfo *common.HostInfo) {
	host := fmt.Sprintf("%s:%s", hostInfo.IP, hostInfo.Port)
	for _, username := range common.UserDict[common.Rtsp] {
		for _, password := range common.Passwords {
			if vulType, success, err := rtspLogin(host, username, password); success && err == nil {
				var description string
				var remediation string
				var userPass common.UserPassDict
				switch vulType {
				case common.RtspWeakPass:
					description = common.RtspWeakPassDescription
					remediation = common.WeakPassRemediation
					userPass.UserName = username
					userPass.PassWord = password
				case common.RtspUnauthenticatedLogin:
					description = common.RtspWeakPassDescription
					remediation = common.UnauthenticatedRemediation
				}
				now := time.Now()
				vulInfo := common.Vul{
					CreateTime:     now,
					VulLevel:       common.HighLevel,
					VulName:        vulType,
					VulType:        common.WeakPassType,
					Description:    description,
					Remediation:    remediation,
					Host:           host,
					Ip:             hostInfo.IP,
					Port:           hostInfo.Port,
					WeakPass:       userPass,
					LatestFindTime: now,
				}
				fmt.Println(vulInfo)
				common.SaveVulInfo(vulInfo)
				switch vulType {
				case common.RtspUnauthenticatedLogin:
					return
				default:
					break
				}
			}
		}
	}

}

func getAuthHeader(reqHeader, respHeader, username, password string) (string, bool) {
	var authType string
	var Authenticate string
	var success bool
	authTypeRegex, _ := regexp.Compile("(Digest|Basic)")
	authType = authTypeRegex.FindString(respHeader)
	switch authType {
	case common.Digest:
		var realm string
		var nonce string

		authRegex, _ := regexp.Compile("WWW-Authenticate:.*")
		auth := authRegex.FindString(respHeader)
		tmp := strings.Split(auth, ",")
		for _, i := range tmp {
			realmRegex, _ := regexp.Compile("realm=\".*\"")
			nonceRegex, _ := regexp.Compile("nonce=\".*\"")
			if strings.Contains(i, "realm=") {
				realm = realmRegex.FindString(i)
				realm = strings.TrimSuffix(realm, "\"")
				realm = strings.TrimPrefix(realm, "realm=\"")
			}
			if strings.Contains(i, "nonce=") {
				nonce = nonceRegex.FindString(i)
				nonce = strings.TrimSuffix(nonce, "\"")
				nonce = strings.TrimPrefix(nonce, "nonce=\"")
			}
		}
		Authenticate = fmt.Sprintf("Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=/, response=\"%s\"\r\n", username, realm, nonce, getDigestResponse(username, password, realm, nonce))
	case common.Basic:
		Authenticate = fmt.Sprintf("Authorization: %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password))))
	default:
		unAuthHeader, _ := regexp.Compile(common.LoginSuccess)
		if unAuthHeader.MatchString(respHeader) {
			success = true
		}
	}

	authHeader := reqHeader + Authenticate + "\r\n"
	return authHeader, success

}

func getReqHeader(host string) (header string) {
	header = fmt.Sprintf("DESCRIBE rtsp://%s RTSP/1.0\r\n", host)
	header += "CSeq: 2\r\n"
	header += "RTSP Client\r\n"
	return header
}

func getDigestResponse(username, password, realm, nonce string) string {
	ha1 := md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", username, realm, password)))
	ha2 := md5.Sum([]byte(fmt.Sprintf("DESCRIBE:%s", "/")))
	response := md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", hex.EncodeToString(ha1[:]), nonce, hex.EncodeToString(ha2[:]))))
	return hex.EncodeToString(response[:])
}

func rtspLogin(host, username, password string) (vulType string, success bool, err error) {
	reqHeader := getReqHeader(host)
	conn, err := net.DialTimeout(common.Tcp, host, time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return "", false, err
	}
	defer conn.Close()
	if _, err = conn.Write([]byte(reqHeader + "\r\n")); err != nil {
		return
	}

	resp := make([]byte, 512)
	var length int
	if length, err = conn.Read(resp); err != nil {
		return "", false, err
	}

	respHeader := string(resp[:length])
	authHeader, success := getAuthHeader(reqHeader, respHeader, username, password)
	if success {
		return common.RtspUnauthenticatedLogin, true, nil

	}

	if authHeader == "" {
		return "", false, nil
	}

	if _, err = conn.Write([]byte(authHeader)); err != nil {
		return "", false, err
	}

	if length, err = conn.Read(resp); err != nil {
		return "", false, err
	}

	if strings.Contains(string(resp[:length]), common.LoginSuccess) {
		return common.RtspWeakPass, true, nil
	}
	return "", false, nil
}

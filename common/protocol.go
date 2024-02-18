package common

var (
	SshProtocol       = `5353482d`
	MysqlProtocol     = `4a0000000a|6d7973716c`
	VmwareProtocol    = `32323020564d776172652041757468656e7469636174696f6e`
	PostgresProtocol  = `^450000008b53464154414c0056464154414c0`
	RmiProtocol       = `^4e..[0-9a-f:.]+0000..`                                      //已测试
	OracleProtocol    = `(?i)284445534352495054494f4e3d28544d503d292856534e4e554d3d`  //已测试
	Socks5Protocol    = `^0500`                                                       //已测试
	MssqlProtocol     = `^0401002500000100000015000601001b000102001c000103001d0000ff` //已测试
	MemcachedProtocol = `^5354415420706964`
	RedisProtocol     = `2d45525220756e6b6e6f776e20636f6d6d616e64202768656c7027`
	RtspProtocol      = `525453502f312e30` //已测试
	HttpProtocol      = `(485454502f312e|3c68746d6c3e)`
	HttpsProtocol     = `^(1603|1503)(01|02|03|04)`
	ZookeeperProtocol = `5a6f6f6b65657065722076657273696f6e3a`
	MongodbProtocol   = `6c6f63616c54696d65`         //已测试
	OnvifProtocol     = `7777772e6f6e7669662e6f7267` //已测试
	RsyncProtocol     = `405253594e4344`             //已测试
	AMQPProtocol      = `414d5150`
	ActiveMQProtocol  = `4163746976654d51` //已测试
	VncProtocol       = `5524642`          //已测试
	DockerProtocol    = `5c7831355c7830335c7830335c7830305c7830325c78303250`
	WebSocketProtocol = `5365632d576562536f636b65742d56657273696f6e`
)

var (
	RmiProbe       = `4a524d4900024b`
	OracleProbe    = `005a0000010000000136012c000008007fff7f08000000010020003a0000000000000000000000000000000034e600000001000000000000000028434f4e4e4543545f444154413d28434f4d4d414e443d76657273696f6e2929`
	Socks5Probe    = `050400010280050100030a` //google.com0050GET / HTTP/1.0\r\n\r\n
	MssqlProbe     = `1201003400000000000015000601001b000102001c000c0300280004ff080001550000004d5353514c53657276657200480f0000`
	MemcachedProbe = `73746174730d0a`
	PostgresProbe  = `000000a4ff534d4272000000000801400000000000000000000000000000400600000100008100025043204e4554574f524b2050524f4752414d20312e3000024d4943524f534f4654204e4554574f524b5320312e303300024d4943524f534f4654204e4554574f524b5320332e3000024c414e4d414e312e3000024c4d312e3258303032000253616d626100024e54204c414e4d414e20312e3000024e54204c4d20302e313200`
	RedisProbe     = `2a310d0a24340d0a68656c700d0a` //已测试
	RtspProbe      = `4f5054494f4e53202f20525453502f312e300d0a0d0a`
	MongodbProbe   = `3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000`
	HttpProbe      = `<?xml version="1.0" encoding="UTF-8"?><soap-env:Envelope xmlns:soap-env="http://www.w3.org/2003/05/soap-envelope" xmlns:soap-enc="http://www.w3.org/2003/05/soap-encoding" xmlns:wsaw="http://www.w3.org/2006/05/addressing/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:onvif="http://www.onvif.org/ver10/schema" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:wsntw="http://docs.oasis-open.org/wsn/bw-2" xmlns:wsrf-rw="http://docs.oasis-open.org/wsrf/rw-2" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:xmime="http://www.w3.org/2005/05/xmlmime"><soap-env:Header/><soap-env:Body><tds:GetDeviceInformation/></soap-env:Body></soap-env:Envelope>`
	HttpsProbe     = `16030100ea010000e6030388cf1ed789499a172355cef54d22cef85ea3f6b6a06e8b7907cbd3b7199d4e8c20c5d7d079ea3d8d0d6b85787587c923f3cca4fd991011fba50c31b6bde2b08b530026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a13011302130301000077000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000120000002b00050403040303003300260024001d002069c2cd65efc4f4796a69a13f8d266d4fda82bff42e063ddd937f6971b99fe35d`
)

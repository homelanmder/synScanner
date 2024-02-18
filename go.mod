module github.com/homelanmder/synScanner

go 1.20

require (
	github.com/DataDog/gostackparse v0.7.0
	github.com/Knetic/govaluate v3.0.0+incompatible
	github.com/Masterminds/semver/v3 v3.2.1
	github.com/Mzack9999/gcache v0.0.0-20230410081825-519e28eab057
	github.com/PuerkitoBio/goquery v1.8.1
	github.com/akrylysov/pogreb v0.10.1
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b
	github.com/antchfx/htmlquery v1.3.0
	github.com/antchfx/xmlquery v1.3.18
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2
	github.com/aws/aws-sdk-go-v2 v1.25.0
	github.com/aws/aws-sdk-go-v2/config v1.27.0
	github.com/aws/aws-sdk-go-v2/credentials v1.17.0
	github.com/beevik/etree v1.1.0
	github.com/bits-and-blooms/bloom/v3 v3.5.0
	github.com/bluele/gcache v0.0.2
	github.com/cloudflare/cfssl v1.6.4
	github.com/corpix/uarand v0.2.0
	github.com/denisenkom/go-mssqldb v0.12.3
	github.com/dimchansky/utfbom v1.1.1
	github.com/docker/go-units v0.5.0
	github.com/fatih/structs v1.1.0
	github.com/go-playground/validator/v10 v10.4.1
	github.com/go-sql-driver/mysql v1.7.1
	github.com/gobwas/ws v1.3.2
	github.com/google/gopacket v1.1.19
	github.com/h2non/filetype v1.1.3
	github.com/hashicorp/golang-lru/v2 v2.0.6
	github.com/hdm/jarm-go v0.0.7
	github.com/huin/asn1ber v0.0.0-20120622192748-af09f62e6358
	github.com/icodeface/tls v0.0.0-20230910023335-34df9250cd12
	github.com/itchyny/gojq v0.12.14
	github.com/jlaffaye/ftp v0.2.0
	github.com/json-iterator/go v1.1.12
	github.com/lib/pq v1.10.9
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/lor00x/goldap v0.0.0-20180618054307-a546dffdd1a3
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40
	github.com/mdlayher/arp v0.0.0-20220512170110-6706a2966875
	github.com/mholt/archiver v3.1.1+incompatible
	github.com/miekg/dns v1.1.56
	github.com/pkg/errors v0.9.1
	github.com/projectdiscovery/clistats v0.0.20
	github.com/projectdiscovery/dnsx v1.1.6
	github.com/projectdiscovery/dsl v0.0.44
	github.com/projectdiscovery/fasttemplate v0.0.2
	github.com/projectdiscovery/goflags v0.1.40
	github.com/projectdiscovery/gologger v1.1.12
	github.com/projectdiscovery/interactsh v1.1.8
	github.com/projectdiscovery/mapcidr v1.1.16
	github.com/projectdiscovery/networkpolicy v0.0.7
	github.com/projectdiscovery/ratelimit v0.0.29
	github.com/projectdiscovery/retryabledns v1.0.54
	github.com/projectdiscovery/retryablehttp-go v1.0.46
	github.com/projectdiscovery/uncover v1.0.7
	github.com/projectdiscovery/utils v0.0.78
	github.com/projectdiscovery/wappalyzergo v0.0.109
	github.com/remeh/sizedwaitgroup v1.0.0
	github.com/rs/xid v1.5.0
	github.com/segmentio/ksuid v1.0.4
	github.com/sijms/go-ora/v2 v2.8.9
	github.com/spf13/cast v1.6.0
	github.com/stacktitan/smb v0.0.0-20190531122847-da9a425dceb8
	github.com/stretchr/testify v1.8.4
	github.com/syndtr/goleveldb v1.0.0
	github.com/tidwall/buntdb v1.3.0
	github.com/twmb/murmur3 v1.1.8
	github.com/ulule/deepcopier v0.0.0-20200430083143-45decc6639b6
	github.com/use-go/onvif v0.0.9
	github.com/valyala/fasthttp v1.52.0
	github.com/weppos/publicsuffix-go v0.30.2-0.20230730094716-a20f9abcc222
	github.com/zmap/zcrypto v0.0.0-20230814193918-dbe676986518
	go.etcd.io/bbolt v1.3.7
	go.mongodb.org/mongo-driver v1.14.0
	go.uber.org/multierr v1.11.0
	golang.org/x/crypto v0.19.0
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d
	golang.org/x/net v0.21.0
	golang.org/x/text v0.14.0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	moul.io/http2curl v1.0.0
)

require (
	aead.dev/minisign v0.2.0 // indirect
	git.mills.io/prologic/smtpd v0.0.0-20210710122116-a525b76c287a // indirect
	github.com/Mzack9999/go-http-digest-auth-client v0.6.1-0.20220414142836-eb8883508809 // indirect
	github.com/Mzack9999/ldapserver v1.0.2-0.20211229000134-b44a0d6ad0dd // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/alecthomas/chroma v0.10.0 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/antchfx/xpath v1.2.4 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.15.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.19.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.22.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.27.0 // indirect
	github.com/aws/smithy-go v1.20.0 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/bits-and-blooms/bitset v1.8.0 // indirect
	github.com/caddyserver/certmagic v0.19.2 // indirect
	github.com/charmbracelet/glamour v0.6.0 // indirect
	github.com/cheggaaa/pb/v3 v3.1.4 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/cnf/structhash v0.0.0-20201127153200-e1b16c1ebc08 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/denisbrodbeck/machineid v1.0.1 // indirect
	github.com/dlclark/regexp2 v1.8.1 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/elgs/gostrgen v0.0.0-20161222160715-9d61ae07eeae // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/go-playground/locales v0.13.0 // indirect
	github.com/go-playground/universal-translator v0.17.0 // indirect
	github.com/goburrow/cache v0.1.4 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gofrs/uuid v3.3.0+incompatible // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.1.4 // indirect
	github.com/google/go-github/v30 v30.1.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/itchyny/timefmt-go v0.1.5 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/juju/errors v0.0.0-20220331221717-b38fca44723b // indirect
	github.com/kataras/jwt v0.1.8 // indirect
	github.com/klauspost/compress v1.17.6 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/leodido/go-urn v1.2.0 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mackerelio/go-osstat v0.2.4 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/mdlayher/ethernet v0.0.0-20220221185849-529eae5b6118 // indirect
	github.com/mdlayher/packet v1.0.0 // indirect
	github.com/mdlayher/socket v0.2.1 // indirect
	github.com/mholt/acmez v1.2.0 // indirect
	github.com/mholt/archiver/v3 v3.5.1 // indirect
	github.com/microcosm-cc/bluemonday v1.0.25 // indirect
	github.com/minio/selfupdate v0.6.1-0.20230907112617-f11e74f84ca7 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/montanaflynn/stats v0.0.0-20171201202039-1bf9dbcd8cbe // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.15.1 // indirect
	github.com/nwaples/rardecode v1.1.3 // indirect
	github.com/olekukonko/tablewriter v0.0.5 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pierrec/lz4/v4 v4.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/projectdiscovery/asnmap v1.0.6 // indirect
	github.com/projectdiscovery/blackrock v0.0.1 // indirect
	github.com/projectdiscovery/cdncheck v1.0.9 // indirect
	github.com/projectdiscovery/fastdialer v0.0.57 // indirect
	github.com/projectdiscovery/freeport v0.0.5 // indirect
	github.com/projectdiscovery/gostruct v0.0.2 // indirect
	github.com/projectdiscovery/hmap v0.0.37 // indirect
	github.com/quic-go/quic-go v0.38.1 // indirect
	github.com/refraction-networking/utls v1.5.4 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/sashabaranov/go-openai v1.14.2 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/tidwall/btree v1.6.0 // indirect
	github.com/tidwall/gjson v1.16.0 // indirect
	github.com/tidwall/grect v0.1.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/rtred v0.1.2 // indirect
	github.com/tidwall/tinyqueue v0.1.1 // indirect
	github.com/ulikunitz/xz v0.5.11 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/yl2chen/cidranger v1.0.2 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	github.com/yuin/goldmark v1.5.4 // indirect
	github.com/yuin/goldmark-emoji v1.0.1 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	github.com/zmap/rc2 v0.0.0-20190804163417-abaa70531248 // indirect
	go.uber.org/zap v1.25.0 // indirect
	goftp.io/server/v2 v2.0.1 // indirect
	golang.org/x/mod v0.13.0 // indirect
	golang.org/x/oauth2 v0.11.0 // indirect
	golang.org/x/sync v0.4.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/tools v0.14.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/corvus-ch/zbase32.v1 v1.0.0 // indirect
	gopkg.in/djherbis/times.v1 v1.3.0 // indirect
)

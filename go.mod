module github.com/T-Systems-MMS/keepassxc-p11-wrapper

go 1.17

require (
	github.com/gopasspw/pinentry v0.0.2
	github.com/miekg/pkcs11 v1.1.1
	github.com/sirupsen/logrus v1.8.1
	pault.ag/go/pkcs7 v0.0.0-20170119163022-efef219101cd
)

replace (
	pault.ag/go/pkcs7 => github.com/jandd/go-pkcs7 v0.0.0-20220513072854-5a44e685aaf0
	pault.ag/go/pkcs7 v0.0.0-20170119163022-efef219101cd => github.com/jandd/go-pkcs7 v0.0.0-20220513072854-5a44e685aaf0
)

require (
	github.com/stretchr/testify v1.7.0 // indirect
	golang.org/x/sys v0.0.0-20211117180635-dee7805ff2e1 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

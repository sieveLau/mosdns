module github.com/sieveLau/mosdns/v4-maintenance

go 1.24.3

require (
	github.com/AdguardTeam/dnsproxy v0.75.6
	github.com/Knetic/govaluate v3.0.0+incompatible
	github.com/fsnotify/fsnotify v1.9.0
	github.com/go-redis/redis/v8 v8.11.5
	github.com/go-viper/mapstructure/v2 v2.3.0
	github.com/golang/snappy v1.0.0
	github.com/google/nftables v0.3.0
	github.com/kardianos/service v1.2.2
	github.com/miekg/dns v1.1.66
	github.com/mitchellh/mapstructure v1.5.0
	github.com/nadoo/ipset v0.5.0
	github.com/pires/go-proxyproto v0.8.1
	github.com/prometheus/client_golang v1.22.0
	github.com/quic-go/quic-go v0.52.0
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	github.com/stretchr/testify v1.10.0
	go.uber.org/zap v1.27.0
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/exp v0.0.0-20250531010427-b6e5de432a8b
	golang.org/x/net v0.41.0
	golang.org/x/sync v0.15.0
	golang.org/x/sys v0.33.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/nadoo/ipset v0.5.0 => github.com/IrineSistiana/ipset v0.5.1-0.20220703061533-6e0fc3b04c0a

require (
	github.com/AdguardTeam/golibs v0.32.11 // indirect
	github.com/ameshkov/dnscrypt/v2 v2.4.0 // indirect
	github.com/ameshkov/dnsstamps v1.0.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20250602020802-c6617b811d0e // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/ginkgo/v2 v2.23.4 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.64.0 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/sagikazarmark/locafero v0.9.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/spf13/cast v1.8.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.uber.org/mock v0.5.2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
)

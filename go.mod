module stayinalived

go 1.18

//replace github.com/davidcoles/vc5 => ./vc5
replace github.com/davidcoles/vc5 => ../vc5

require (
	github.com/cloudflare/ipvs v0.10.0
	github.com/davidcoles/vc5 v0.1.19-0.20230902111436-12d855db0c3c
)

require (
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/lrh3321/ipset-go v0.0.0-20230425010353-0d9880b1ecac // indirect
	github.com/mdlayher/genetlink v1.3.1 // indirect
	github.com/mdlayher/netlink v1.7.1 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/vishvananda/netlink v1.2.1-beta.2 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/net v0.2.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
)

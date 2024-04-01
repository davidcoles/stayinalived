# stayinalived

IPVS based loadbalancer: `cd cmd && make stayinalived`

This is a fork of the [vc5](https://github.com/davidcoles/vc5) load
balancer which uses
[IPVS](https://en.wikipedia.org/wiki/IP_Virtual_Server) instead of an
[eBPF/XDP](https://github.com/davidcoles/xvs) based load balancing
engine.

Currently this operates in full NAT mode so, unlike with vc5, you need
to do some work with iptables and friends to make this work (see
garbled notes below).


Changes in vc5 will be merged in to the code here frequently so new
features such as logging improvements should appear in a timely manner.

## NOTES

Before running ...

```
MY_ADDRESS=$(hostname -I | cut -d' ' -f1)

modprobe ip_vs
sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.vs.conntrack=1
#sysctl net.ipv4.vs.snat_reroute=1
iptables -t nat -A POSTROUTING -m ipvs --ipvs -j SNAT --to-source $MY_ADDRESS
```

to prevent packets accidentally hitting local services if there's no IPVS service to handle them
set up an fwmark catchall service with no destinations and mark all traffic to virtual addresses:

```
ipvsadm -A -f 666 -s rr
iptables -A PREROUTING -t mangle -d 192.168.101.0/24 -j MARK --set-mark 666
```

then explictly mark desired service to bypass the catchall

```
iptables -A PREROUTING -t mangle -d 192.168.101.1/32 -p tcp --dport 80 -j MARK --set-mark 1
iptables -A PREROUTING -t mangle -d 192.168.101.2/32 -p tcp --dport 80 -j MARK --set-mark 1
```

I will probably do the iptables rules with an ipset that the LB will
add/remove services from (indeed, this is implemented with the -s flag
now, and the ipset will be created for you automatically):

```
ipset create ipvs hash:ip,port
iptables -A PREROUTING -t mangle -m set --match-set ipvs dst,dst -j MARK --set-mark 1
```

You could now add an accept rule to packets matching the 'ipvs' set
and then drop all other packets to the VIPs.


Create the VIP addresses locally - IPVS doesn't seem to handle the traffic
unless present.  I would dearly like to know if it is possible to
avoid this - the -i flag now indicates an interface on which addresses
will be automatically added/removed.

```
ip link add ipvs type dummy
ip a add 192.168.101.1/32 dev ipvs
ip a add 192.168.101.2/32 dev ipvs
ip a add 192.168.101.3/32 dev ipvs
ip a add 192.168.101.4/32 dev ipvs
ip a add 192.168.101.5/32 dev ipvs
```


To mitigate port exhaustion with SNAT, it might be an idea to add an
extra IP addresses to use exclusively for NAT purposes.

```
iptables -t nat -A POSTROUTING -m ipvs --ipvs -j SNAT --to-source 10.1.2.10
```


TCP MSS adjustment??

```
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1440 -m set --match-set ipip src,src

```


cat >>/etc/modules <<EOF
ip_vs_wlc
ip_vs_mh
ip_vs_lc
ip_vs_wrr
ip_vs_rr
ip_vs
EOF

cat >>/etc/sysctl.conf <<EOF
net.ipv4.ip_forward=1
net.ipv4.vs.conntrack=1
EOF

ipset create ipvs hash:ip,port
ipvsadm -A -f 666 -s rr
iptables -A PREROUTING -t mangle -d 192.168.101.0/24 -j MARK --set-mark 666
iptables -A PREROUTING -t mangle -m set --match-set ipvs dst,dst -j MARK --set-mark 1
iptables -A POSTROUTING -t nat -m ipvs --ipvs -j SNAT --to-source $(hostname -I | cut -d' ' -f1)
```

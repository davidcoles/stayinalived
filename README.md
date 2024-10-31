# stayinalived

IPVS based loadbalancer: `cd cmd && make stayinalived`

This is a fork of the [vc5](https://github.com/davidcoles/vc5) load
balancer which uses
[IPVS](https://en.wikipedia.org/wiki/IP_Virtual_Server) instead of the 
[xvs](https://github.com/davidcoles/xvs) eBPF/XDP based load balancing
engine.

Currently this operates in full NAT mode so, unlike with vc5, you need
to do some work with iptables and friends to make this work (see
garbled notes below).


Changes in vc5 will be merged in to the code here frequently(-ish) so
new features such as logging improvements should appear eventually.

## NOTES

Before running ...

Make sure that the kernel module is loaded and that outging packets
will be NATted as coming from the load balancer (IPVS doesn't seem to
do this automatically):
     
```  
MY_ADDRESS=$(hostname -I | cut -d' ' -f1)
		      
modprobe ip_vs
sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.vs.conntrack=1
#sysctl net.ipv4.vs.snat_reroute=1 # not needed
iptables -t nat -A POSTROUTING -m ipvs --ipvs -j SNAT --to-source $MY_ADDRESS
```

To prevent packets accidentally hitting local services if there is no
IPVS service to handle them, set up an fwmark catchall service with no
destinations and mark all traffic received for the virtual address
range (192.168.101.0/24 in this example):

```
ipvsadm -A -f 666 -s rr
iptables -A PREROUTING -t mangle -d 192.168.101.0/24 -j MARK --set-mark 666
```

Then we could explictly mark service to bypass the catchall, eg.:

```
iptables -A PREROUTING -t mangle -d 192.168.101.1/32 -p tcp --dport 80 -j MARK --set-mark 1
iptables -A PREROUTING -t mangle -d 192.168.101.2/32 -p tcp --dport 80 -j MARK --set-mark 1
```

Instead, stayinalived achieves the above by adding services to an IP
set. Create one and add a rule that will mark services:

```
ipset create ipvs hash:ip,port
iptables -A PREROUTING -t mangle -m set --match-set ipvs dst,dst -j MARK --set-mark 1
```

IPVS doesn't seem to handle the traffic unless the VIP is present on
the local system. I would dearly like to know if it is possible to
avoid this. VIPs could be added manually, but stayinalived can manage
them for you. Create a dummy interface where the VIPs will be assigned:

```
ip link add ipvs type dummy
```

When stayinalived is run, you have it manage your ipset (-s) and
interface (-i) automatically as services and VIPs come and go:

`./stayinalived -s ipvs -i ipvs $MY_ADDRESS stayinalived.json`


To mitigate port exhaustion with SNAT, it might be an idea to add an
extra IP addresses to use exclusively for NAT purposes. Eg.:

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

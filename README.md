# stayinalived

IPVS based loadbalancer: `make stayinalived`

See https://github.com/davidcoles/vc5 for list of dependencies that need to be installed.

Very early work, not really for public consumption.

## NOTES

Before running ...

```
MY_ADDRESS=$(hostname -I | cut -d' ' -f1)

modprobe ip_vs
sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.vs.conntrack=1
sysctl net.ipv4.vs.snat_reroute=1
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


I will probably do the iptables rules with an ipset that the LB will add/remove services from

create the addresses locally - IPVS doesn't seem to handle the traffic unless present.
I would dearly like to know if it is possible to avoid this

```
ip link add ipvs type dummy
ip a add 192.168.101.1/32 dev ipvs
ip a add 192.168.101.2/32 dev ipvs
```

To mitigate port exhaustion with SNAT, it might be an idea to add some
extra IP addresses to use exclusively for NAT purposes. To balance
between them we could use a netmask:

```
iptables -t nat -A POSTROUTING -m ipvs --ipvs -j SNAT --to-source 10.1.2.10 -s 0.0.0.0/0.0.0.1
iptables -t nat -A POSTROUTING -m ipvs --ipvs -j SNAT --to-source 10.1.2.11 -s 0.0.0.1/0.0.0.1
```

We'd need a power of two addresses for (hopefully) equal allocation:

```
iptables -t nat -A POSTROUTING -m ipvs --ipvs -j SNAT --to-source 10.1.2.10 -s 0.0.0.0/0.0.0.3
iptables -t nat -A POSTROUTING -m ipvs --ipvs -j SNAT --to-source 10.1.2.11 -s 0.0.0.1/0.0.0.3
iptables -t nat -A POSTROUTING -m ipvs --ipvs -j SNAT --to-source 10.1.2.12 -s 0.0.0.2/0.0.0.3
iptables -t nat -A POSTROUTING -m ipvs --ipvs -j SNAT --to-source 10.1.2.13 -s 0.0.0.3/0.0.0.3
```

Maybe there's an easier way - answers on a postcard, please!

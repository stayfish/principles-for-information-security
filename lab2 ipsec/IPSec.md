# 基于 linux 搭建 IPSec-VPN

---

[TOC]

---

## 实验环境 

| 服务端系统 | Ubuntu 20.04.5     |
| ---------- | ------------------ |
| 客户端系统 | Ubuntu 20.04.5     |
| 开源程序库 | xl2tpd、strongswan |

## 配置过程



### 服务端配置

1. 在服务端安装 xl2tpd 和 strongswan

2. 配置 `/etc/ipsec.conf` 文件

   配置如下

   ```shell
   version 2
   config setup
   conn L2TP-PSK-noNAT
       authby=secret
       auto=add
       keyingtries=3
       ikelifetime=8h
       keylife=1h
       ike=aes256-sha1
       esp=aes256-sha1
       type=transport
       #left这里写的是服务器的IP地址
       left=192.168.205.132
       leftprotoport=17/1701
       right=%any
       rightprotoport=17/%any
       dpddelay=10
       dpdtimeout=20
       dpdaction=clear
   ```

   文件中的 ike 可以设定采用的 ike 方法

3. 配置 `/etc/ipsec.secrets` 文件

   在该文件中设置共享密钥，设置为 012345

   ```shell
   {0} %any : PSK "012345"
   ```

   在 `{0}` 处添加服务器的地址

4. 配置 `/etc/xl2tpd/xl2tpd.conf`

   ```shell
   [global]
   ipsec saref = yes
   saref refinfo = 30
   ;debug avp = yes
   ;debug network = yes
   debug state = yes
   ;debug tunnel = yes
   [lns default]
   ip range = {0}
   local ip = {1} 
   refuse pap = yes
   require authentication = yes
   ppp debug = yes
   pppoptfile = /etc/ppp/options.xl2tpd
   length bit = yes
   ```

   文件中的 `{0}` 处是为连接 VPN 的用户分配的 IP 地址，`{1}` 处是服务器的 IP 地址

   文件还定义了 pppoptfile 的路径

5. 配置 `etc/ppp/options.xl2tpd` 

   配置为 

   ```shell
   require-mschap-v2
   ms-dns 8.8.8.8
   ms-dns 114.114.114.114
   auth
   mtu 1200
   mru 1000
   crtscts
   hide-password
   modem
   name l2tpd
   proxyarp
   lcp-echo-interval 30
   lcp-echo-failure 4
   ```

6. 配置 `etc/ppp/chap-secrets` 

   配置为 

   ```shell
   ruoy l2tpd 123456 *
   ```

   配置的格式为

   | client | server                   | secret   | IP Address       |
   | ------ | ------------------------ | -------- | ---------------- |
   | 用户名 | ppp.options 中定义的名字 | 用户密码 | 能接受的 IP 地址 |

7. 配置完成后，需要重启服务

   ```shell
   # sudo systemctl ipsec restart
   sudo ipsec restart
   sudo service xl2tpd restart
   ```
   
   

### 客户端配置

1. 下载 L2TP 网络连接的 GUI

   `sudo apt install network-manager-l2tp-gnome`

   安装前的添加 VPN 界面

   <img src="D:\workspace\course\信息安全原理\assignment\ipsec\imgs\before.png" style="zoom: 50%;" />

   安装后的 添加 VPN 界面为

   <img src="D:\workspace\course\信息安全原理\assignment\ipsec\imgs\after.png" style="zoom:50%;" />

2. 添加 L2TP VPN

   在 Add VPN 中选择 Layer 2 Tunneling Protocol(L2TP)，配置 L2TP VPN 用户密码

   ![l2tp](D:\workspace\course\信息安全原理\assignment\ipsec\imgs\l2tp.png)
   
   保存后，连接 VPN，然后用 `ifconfig` 指令查看当前的 IP
   
   此时的 IP 为
   
   ![1679643236913](D:\workspace\course\信息安全原理\assignment\ipsec\imgs\ifconfig.png)
   
   
   
   

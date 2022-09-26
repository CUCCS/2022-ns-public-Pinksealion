# 基于 VirtualBox 的网络攻防基础环境搭建

## 实验目的

- 掌握 VirtualBox 虚拟机的安装与使用；
- 掌握 VirtualBox 的虚拟网络类型和按需配置；
- 掌握 VirtualBox 的虚拟硬盘多重加载；

## 实验环境

以下是本次实验需要使用的网络节点说明和主要软件举例：

- VirtualBox 虚拟机
- 攻击者主机（Attacker）：Kali Rolling 2019.2
- 网关（Gateway, GW）：Debian Buster
- 靶机（Victim）：From Sqli to shell / xp-sp3 / Kali

## 实验要求

- 虚拟硬盘配置成**多重加载**

- 搭建满足如下拓扑图所示的虚拟机网络拓扑；

  ![topological_graph](img/topological_graph.jpg)

> 根据实验宿主机的性能条件，可以适度精简靶机数量

- 完成以下网络连通性测试；
  - - [x] 靶机可以直接访问攻击者主机
  - - [x] 攻击者主机无法直接访问靶机
  - - [x] 网关可以直接访问攻击者主机和靶机
  - - [x]  靶机的所有对外上下行流量必须经过网关
  - - [x] 所有节点均可以访问互联网

## 实验步骤

### 1.虚拟硬盘配置多重加载

在VirtualBox管理界面进入**虚拟介质管理**，选中需改的虚拟盘后将属性中的**类型**修改为多重加载

![multi-load](img/multi_load.jpg)

### 2.搭建满足拓扑图的虚拟机网络拓扑

由图可知，gateway需要四块网卡，attacker需三块网卡，victim需一块网卡。

**网关（Debian-gateway）**

| 网卡  |                     设置                     |
| :---: | :------------------------------------------: |
| 网卡1 | NAT网络（非NAT网络），实现与外部攻击者的联系 |
| 网卡2 |             仅主机（Host-Only）              |
| 网卡3 |          内部网络，局域网internet1           |
| 网卡4 |          内部网络，局域网internet2           |

![gateway_network_card](img/gateway_network_card.jpg)

**攻击者（Kali-Attacker）**

| 网卡  |                  设置                   |
| :---: | :-------------------------------------: |
| 网卡1 | 网络地址转换，NAT网络，实现与网关的联系 |
| 网卡2 |           仅主机（Host-Only）           |
| 网卡3 |           仅主机（Host-Only）           |

![attacker_network_card](img/attacker_network_card.jpg)

**靶机（Vicitm-XP-1/Victim-Kali-1/Victim-Debian-2/Victim-XP-2）**

设置为内部网络，根据拓扑图分别选择局域网。

![victim_network_card](img/victim_network_card.jpg)

### 3.网络连通性测试

3.1靶机可以直接访问攻击者主机

- intnet1

  ![intnet1_accesses_attacker](img/intnet1_accesses_attacker.jpg)

- intnet2

  ![intnet2_accesses_attacker](img/intnet2_accesses_attacker.jpg)

3.2攻击者主机无法直接访问靶机

靶机使用的ip地址仅内部网络（局域网1/局域网2）可用（如图所示）

![intnet1_Kali-1_ping_XP-1](img/intnet1_Kali-1_ping_XP-1.jpg)

而攻击者无法访问。

- intnet1

  ![attacker_accesses_intnet1](img/attacker_accesses_intnet1.jpg)

- intnet2

  ![attacker_accesses_intnet2.jpg](img/attacker_accesses_intnet2.jpg)

3.3网关可以直接访问攻击者主机和靶机

- attacker

  ![gateway_accesses_attacker](img/gateway_accesses_attacker.jpg)

- victim

  - intnet1

    ![gateway_accesses_intnet1](img/gateway_accesses_intnet1.jpg)

  - intnet2
  
    ![gateway_accesses_intnet2](img/gateway_accesses_intnet2.jpg)

3.4靶机的所有对外上下行流量必须经过网关

靶机ping互联网，用网关抓包，如果靶机发送的所有包都能被网关抓到则得证。

```bash
  # 网关抓包
  $ sudo tcpdump -c 5
  
  # tcpdump更新
  $ apt update && aptinstall tmux
  
  # 抓包参考
  $ tcpdump -i enp0s9 -n -w 20210908.1.pcap
  
  # 抓包操作
  $ tcpdump -i enp0s9 -n -2 20220923.1.pcap
```

- 局域网1靶机

  ![gateway_traffic_monitoring_intnet1](img/gateway_traffic_monitoring_intnet1.jpg)

- 局域网2靶机

  ![gateway_traffic_monitoring_intnet2](img/gateway_traffic_monitoring_intnet2.jpg)

- 抓包产生的文件scp到本机后分析

  ![gateway_traffic](img/gateway_traffic.jpg)

  发现对应数据均符合，得证。

3.5所有节点均可以访问互联网

- gateway

  ![gateway_accesses_internet](img/gateway_accesses_internet.jpg)

- attacker

  ![attacker_accesses_internet](img/attacker_accesses_internet.jpg)

- victim

  - intnet1

    ![intnet1_accesses_internet](img/intnet1_accesses_internet.jpg)

  - intnet2

    ![intnet2_accesses_internet](img/intnet2_accesses_internet.jpg)

## 实验问题

- 将介质类型从普通更改为多重加载时报错。

  解决：阅读明细后发现是多重加载需要在更高版本上运行，同时路径改为无中文后成功。

- 不清楚如何配置两块不同的Host-Only网卡

  解决：关闭虚拟机，进入管理中的主机网络管理器，在网络中创建新的网卡（开启DHCP服务！）

  ![Q2_Host-Only](img/Q2_Host-Only.jpg)

## 参考资料

- [多重加载功能介绍](https://blog.csdn.net/Jeanphorn/article/details/45056251)
- [Host-Only网卡配置](https://www.likecs.com/show-203630914.html)
- [无法ping通时一些小tips](https://blog.csdn.net/a17377298306/article/details/104829017)
- [NAT网络](https://www.yisu.com/zixun/63512.html)
- [Lychee](https://github.com/CUCCS/2021-ns-public-Lychee00/blob/chap0x01/chap0x01/report01.md)

## 修改

- 网关和攻击者错配置为NAT网卡而非NAT网络，将网关与攻击者更改为NAT网络（图片中粉色部分标注为修改部分）。但之前的连通性测试并未受到影响，询问后得知仅有一块NAT网卡未构建NAT网络无法实现与其他虚拟机相连，之前搭建的网络是通过Host-Only网卡实现了整体的连通性。

  |      网络连接方式       |                             特点                             |
  | :---------------------: | :----------------------------------------------------------: |
  |   网络地址转换（NAT）   |          客户机内一块网卡，可完成本机浏览网页等操作          |
  |         NAT网络         | 类似于“家庭路由器”，将所有使用它的系统归类入一个网络，内部系统间可以互相通信，同时可以抵抗外部系统直接访问内部系统 |
  | 仅主机（Host-Only）网络 | 主机和一组虚拟机组成的网络（无需主机的物理接口），在主机上创建虚拟网络接口，完成主机与虚拟机之间的连接 |

- 删除图片外链、更改了笔误以及Markdown标明列表项完成时打对勾的方式

- 在进行抓包操作`tcpdump -i enp0s9 -n -w 20220923.1.pcap`时文中所引用为师姐作业中代码块（参考资料内补充了师姐的仓库链接），仅作参考使用所以忘记更新为自己的文件名，在后面补充了一条更改为自己文件的代码用以与图片所显示结果相同
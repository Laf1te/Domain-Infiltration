# Kerberos 协议认证原理

在后渗透中，学习制作黄金票据、白银票据都是很重要，他们的原理就是利用了 **Kerberos 协议**中的机制，同时 **Kerberos 协议**也造成了 MS14-068 漏洞、密码喷洒攻击、AS-REP Roasting 攻击等诸多问题，本篇文章就是来了解 Kerberos 协议的运行机制，相信学习过后肯定会对我们的后渗透学习有所帮助。

# 什么是Kerberos 协议

Kerberos 原意是希腊神话中看守冥界入口的恶犬刻耳柏洛斯，类似于「哈利波特·神秘魔法石」中守护魔法石的三头犬毛毛。

Kerberos 是一种计算机网络认证协议，他能够为网络中通信的双方提供严格的身份验证服务，确保通信双方身份的真实性和安全性。

不同于其他网络服务，Kerberos协议中不是所有的客户端向想要访问的网络服务发起请求，他就能够建立连接然后进行加密通信。而是在发起服务请求后必须先进行一系列的身份认证，包括客户端和服务端两方的双向认证，只有当通信双方都认证通过对方身份之后，才可以互相建立起连接，进行网络通信。

在 Kerberos 认证中，最主要的问题就是如何证明**「你是你」**的问题，打个比方来说，当 A 要和 B 进行通信的时候，A 就需要向 B 证明自己是 A，直接的方式就是 A 用二人之间的秘密做秘钥加密明文文字生成密文，把密文和明文文字一块发送给 B，B 再用秘密解密得到明文，把解密出来的明文和另外一起发过来的明文文字进行对比，若一致，则证明对方是 A。

但是的但是，在网络中，密文和文字很有可能被窃取。只要时间足够，总能破解秘钥。所以不能使用这种长期有效的秘钥，要改为短期的临时秘钥，那么这个临时秘钥需要一个第三方可信任的机构来提供，这个机构就是 KDC（Key Distribution Center）秘钥分发中心。

**key 概念**

刚刚我们说过，因为在网络中，需要使用临时秘钥来代替长期有效的秘钥。这里就有两个概念：

1. **Long-term Key/Master Key**
有些长期保持不变的秘钥( Key )，比如你的密码、存储在计算机的 NTLM-Hash 。这样的 Key 被称为 Long-term Key，也叫 Master Key。这样的 Key 不应该在网络上传输，因为容易被截获、被解密。
2. **Short-term Key/Session Key**
短暂临时的 Key 来取代 Master Key，这种 Key 被称为 Short-term Key，也叫 Session Key。用 Session Key 来加密需要进行网络传输的数据。因为这种 Key 只在一段时间内有效，即使被加密的数据包被黑客破解，等他把 Key 计算出来的时候，这个 Key 早就已经过期了。

# Kerberos 协议认证原理

先要了解一下以下几个关键角色：

- Domain Controller：域控制器，简称 DC，一台计算机，实现用户、计算机的统一管理。
- Key Distribution Center：秘钥分发中心，简称 KDC，默认安装在域控里，包括 AS 和 TGS。
- Authentication Service：身份验证服务，简称 AS，用于 KDC 对 Client 认证。
- Ticket Grantng Service：票据授予服务，简称 TGS，用于 KDC 向 Client 和 Server 分发 Session Key（临时秘钥）。
- Active Directory：活动目录，简称 AD，用于存储用户、用户组、域相关的信息。
- Client：客户端，指用户。
- Server：服务端，可能是某台计算机，也可能是某个服务。

先看一下大致的流程图吧：

![Kerberos 协议 (1).png](Kerberos%20%E5%8D%8F%E8%AE%AE%E8%AE%A4%E8%AF%81%E5%8E%9F%E7%90%86%20b06639c6a9dd4bad898283c7036c4dbe/Kerberos_%E5%8D%8F%E8%AE%AE_(1).png)

这里我们可以将认证分为三个阶段：第一阶段：Client 与 AS 的交互（上图的①、②）、第二阶段：Client 与 TGS 的交互（上图的③、④）、第三阶段：Client 与 Server 的交互（上图的⑤、⑥）

下面我们分段来细说：

## 第一阶段：Client 与 Authentication Service

为了获得能够用来访问服务端服务的票据，客户端首先需要来到KDC获得服务授予票据（Ticket）。由于客户端是第一次访问KDC，此时KDC也不确定该客户端的身份，所以**第一次通信的目的为KDC认证客户端身份，确认客户端是一个可靠且拥有访问KDC权限的客户端**

① 客户端用户向 KDC 以明文的方式发起请求：**Client→Authentication Service**，该次请求中携带了自己的用户名、主机IP、和当前时间戳，这个请求类型为：`KRB_AS_REQ` 。

![2.png](Kerberos%20%E5%8D%8F%E8%AE%AE%E8%AE%A4%E8%AF%81%E5%8E%9F%E7%90%86%20b06639c6a9dd4bad898283c7036c4dbe/2.png)

② KDC 当中的 AS（Authentication Server）接收请求（ AS 是 KDC 中专门用来认证客户端身份的认证服务器）后去 Kerberos 认证数据库中根据用户名查找是否存在该用户，此时只会查找是否有相同用户名的用户，并不会判断身份的可靠性。如果没有该用户名，认证失败；如果存在该用户名，则 AS 便认为用户存在，此时 AS 对客户端做出响应：**Authentication Service→Client**，类型为 `KRB_AS_REP` 。

响应内容包含两部分：

- 第一部分：**票据授予票据 TGT**，客户端需要使用 TGT 去密钥分发中心 KDC 中的票据授予服务 TGS 获取访问网络服务所需的 Ticket（服务授予票据），TGT 中包含的内容有： Kerberos 数据库中存在的该客户端的 Name、IP、当前时间戳、客户端即将访问的 TGS 的 Name、TGT的有效时间以及一把用于客户端和 TGS 间进行通信的临时秘钥 Session_Key as(CT_SK)。**AS 使用 KDC 一个特定账户的 NTLM-hash 对 TGT 进行的加密，这个特定账户就是 `krbtgt`** (创建域控时自动生成)，这个加密是客户端无法破解的。
- 第二部分：使用客户端密钥（这个密钥是 AS 认证通过后从 Kerberos 认证数据库中取出的该用户的 NTLM hash）加密的一段内容，这段内容包括：用于客户端和 TGS 之间通信的临时秘钥 Session_Key as (CT_SK) ，客户端即将访问的 TGS 信息以及 TGT 的有效时间和一个当前时间戳。该部分内容使用客户端密钥加密，所以客户端在拿到该部分内容时可以通过自己的密钥解密。

对于 `AS_REP` 中还存在的 PAC 信息这里暂不研究了。

![阶段一2.png](Kerberos%20%E5%8D%8F%E8%AE%AE%E8%AE%A4%E8%AF%81%E5%8E%9F%E7%90%86%20b06639c6a9dd4bad898283c7036c4dbe/%E9%98%B6%E6%AE%B5%E4%B8%802.png)

<aside>
💡 AS_REP 中最核心的东西就是 Session-key 和 TGT。我们平时用 Mimikatz、kekeo、rubeus 等工具生成的凭据是 .kirbi 后缀，Impacket 生成的凭据的后缀是 .ccache。这两种票据主要包含的都是 Session-key 和 TGT，因此可以相互转化。

</aside>

第一阶段终于结束了0.0

## 第二阶段：Client 与 Ticket Grantng Service

Client收到回复 `AS_REP` 后，客户端会用自己的 Client NTLM-hash 将 AS 返回的第二部分内容进行解密，分别获得时间戳、接下来要访问的 TGS 信息以及用于和 TGS 通信的密钥 CT_SK（也就是 Session_key as），首先他会根据时间戳判断该时间戳与自己发送请求时的时间之间的差值是否大于5分钟，如果大于五分钟则认为该 AS 是伪造的，认证至此失败。如果时间戳合理，客户端便准备向 TGS 发起请求。

③ 客户端向 TGS 发起请求，**Client→Ticket Grantng Service**，这次请求类型为：`KRB_TGS_REQ`，请求的内容包含三部分：

- 第一部分：使用 CT_SK 加密的客户端信息、，其中包括：Name、IP、时间戳
- 第二部分：自己想要访问的 Server 服务信息（明文形式）
- 第三部分：AS 返回的 TGT （TGT 是用 krbtgt 账户的 NTLM-hash 加密的，Client 无法解密）
  
    ![阶段二1.png](Kerberos%20%E5%8D%8F%E8%AE%AE%E8%AE%A4%E8%AF%81%E5%8E%9F%E7%90%86%20b06639c6a9dd4bad898283c7036c4dbe/%E9%98%B6%E6%AE%B5%E4%BA%8C1.png)
    

④ TGS 接收到请求，他首先根据客户端明文传输过来的 Server 服务 IP 查看当前 kerberos 系统中是否存在可以被用户访问的该服务。如果不存在，认证失败结束，。如果存在，继续接下来的认证。

TGS 将用 krbtgt 用户的 NTLM-hash 先解密 TGT 中的内容进行解密，此时他看到了经过 AS 认证过后并记录的用户信息、Session_Key as 即 CT_SK，还有时间戳信息

 之后 TGS 会使用 CT_SK 解密客户端发来的第一部分内容，将两部分获取到时间戳 timestamp 进行比较，如果时间戳跟当前时间相差太久，就需要重新认证；TGS 还会将这个 Client 的信息与 TGT 中的 Client 信息进行比较，如果两个相等的话，还会继续判断 Client 有没有权限访问 Server，如果都没有问题，认证成功。

上述认证都成功后，TGS 将向客户端发起响应，**Ticket Grantng Service→Client**，此响应类型为：`KRB_TGS_REP` ，响应信息包含两部分：

- 第一部分：用于客户端访问网络服务的使用服务端加密的ST（Servre Ticket），其中包括客户端 Name、IP、客户端待访问的服务端信息、ST 有效时间、时间戳以及用于客户端和服务端之间通信的 CS_SK（Session Key tgs）。
- 第二部分：使用 CT_SK 加密的内容，其中包括 CS_SK 、时间戳和 ST 的有效时间。由于在第一次通信的过程中，AS 已将 CT_SK 通过客户端密码加密交给了客户端，且客户端解密并缓存了 CT_SK，所以该部分内容在客户端接收到时是可以自己解密的。

> 注意Session-key tgs 主要用在 Client 和 Server 的通信上，而Session_Key as 主要用在 Client 和 Ticket Grantng Service 的通信上。
> 

![阶段二2.png](Kerberos%20%E5%8D%8F%E8%AE%AE%E8%AE%A4%E8%AF%81%E5%8E%9F%E7%90%86%20b06639c6a9dd4bad898283c7036c4dbe/%E9%98%B6%E6%AE%B5%E4%BA%8C2.png)

至此，Client 和 KDC 的通信就结束了，然后是和 Server 进行通信。

## 第三阶段：Client 与 Server

客户端收到来自 TGS 的 `TGS_REP`，并使用本地缓存的 CT_SK 解密出 TGS 返回的第二部分内容（由于 TGS 返回的第一部分信息是用的服务端秘钥加密的，因此这里的客户端是无法进行解密的），检查时间戳无误后，取出 CS_SK 准备向服务端发起请求。

⑤ 客户端向服务端发送请求，`Client→Server`，这次请求类型为：`KRB_AP_REQ` （也有叫 `KRB_SE_REQ`），请求内容包括两部分：

- 第一部分：利用 CS_SK 将自己的主机信息和时间戳进行加密的信息
- 第二部分：第 ④ 步里 TGS 向客户端返回的第一部分内容，即使用服务端密码加密的服务票据 ST
  
    ![阶段三1.png](Kerberos%20%E5%8D%8F%E8%AE%AE%E8%AE%A4%E8%AF%81%E5%8E%9F%E7%90%86%20b06639c6a9dd4bad898283c7036c4dbe/%E9%98%B6%E6%AE%B5%E4%B8%891.png)
    

⑥ 服务端此时收到了来自客户端的请求，它会使用自己的 Server NTLM-hash 解密客户端发来的第二部分内容，核对时间戳之后，获得经过 TGS 认证后的客户端信息，并取出 CS_SK，利用 CS_SK 解密第一部分内容。此时他将这部分信息和客户端第二部分内容带来的自己的信息进行比对，最终确认该客户端就是经过了 KDC 认证的具有真实身份的客户端，是他可以提供服务的客户端。此时服务端返回一段使用 CT_SK 加密的表示接收请求的响应给客户端，该响应类型为：`KRB_AP_REP` （也有叫`KRB_SE_REP`）。

在客户端收到请求之后，使用缓存在本地的CS_ST解密之后也确定了服务端的身份（其实服务端在通信的过程中还会使用数字证书证明自己身份），建立通信

至此，kerberos 认证流程结束。

这里放上两张大佬化的 kerberos 认证的整体流图，一个是 kerberos 认证的时序图，一个是 kerberos 认证的示意图

时序图：

![kerberos6.png](Kerberos%20%E5%8D%8F%E8%AE%AE%E8%AE%A4%E8%AF%81%E5%8E%9F%E7%90%86%20b06639c6a9dd4bad898283c7036c4dbe/kerberos6.png)

示意图：

![ker.png](Kerberos%20%E5%8D%8F%E8%AE%AE%E8%AE%A4%E8%AF%81%E5%8E%9F%E7%90%86%20b06639c6a9dd4bad898283c7036c4dbe/ker.png)

最后的最后，分享一个比较有趣的[文章](https://github.com/SnowMeteors/KerberosPrinciple-Chinese)，以故事对话形式阐述 Kerberos 原理，感觉还是蛮不错的。

参考文章：

[https://www.jianshu.com/p/13758c310242](https://www.jianshu.com/p/13758c310242)

[https://teamssix.com/210923-151418.html#toc-heading-8](https://teamssix.com/210923-151418.html#toc-heading-8)

[https://www.freebuf.com/articles/network/276948.html](https://www.freebuf.com/articles/network/276948.html)

[https://www.freebuf.com/articles/network/273725.html](https://www.freebuf.com/articles/network/273725.html)

[https://www.freebuf.com/articles/network/273725.html](https://www.freebuf.com/articles/network/273725.html)

[https://seevae.github.io/2020/09/12/详解kerberos认证流程/](https://seevae.github.io/2020/09/12/%E8%AF%A6%E8%A7%A3kerberos%E8%AE%A4%E8%AF%81%E6%B5%81%E7%A8%8B/)

[http://81.68.112.193/ltltlxey/内网/125.html](http://81.68.112.193/ltltlxey/%E5%86%85%E7%BD%91/125.html)
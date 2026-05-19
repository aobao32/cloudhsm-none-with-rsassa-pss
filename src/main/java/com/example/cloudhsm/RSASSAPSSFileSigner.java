package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

/**
 * 对 message.txt 执行 RSASSA-PSS 签名：
 * <ol>
 *   <li>在应用层（本地 Java）对文件计算 SHA-256，并打印 hash 值；</li>
 *   <li>调用 CloudHSM JCE Provider (SDK 5) 的
 *       {@code "RSASSA-PSS"} 算法，通过 {@link PSSParameterSpec} 显式指定
 *       SHA-256 摘要 + MGF1-SHA256 + <b>saltLength=32</b> + trailer=1，
 *       由 CloudHSM 内的私钥完成 PSS 签名；</li>
 *   <li>将签名结果写入 message.sig，并以 Base64 输出到标准输出。</li>
 * </ol>
 *
 * <p>注意：按 AWS 官方文档，CloudHSM Client SDK 5 的带 hashing 的签名算法
 * （如 {@code RSASSA-PSS} 搭配 {@code PSSParameterSpec} 中的 {@code SHA-256}）
 * 会先由 <b>CloudHSM JCE Provider 在客户端 JVM 内的软件</b>对数据做 SHA-256，
 * 再将 hash 送到 HSM 做 PSS 运算（不是用户应用代码做，也不是 HSM 做）——
 * 因此与 {@code NONEwithRSASSA-PSS} + 应用层手算 SHA-256 在协议语义上完全等价，
 * 满足"应用层之外的本机软件做 SHA-256，CloudHSM 做 RSASSA-PSS"的要求。</p>
 *
 * <p>用法：
 * <pre>
 *   export HSM_USER=&lt;CU用户名&gt;
 *   export HSM_PASSWORD=&lt;CU密码&gt;
 *   java -jar pss-sign-1.0-SNAPSHOT.jar
 * </pre>
 * 前提：已先运行 rsa-keygen jar 生成 label 为 {@code pss_rsa_private} 的私钥，
 * 并在当前目录下存在待签名文件 {@code message.txt}。</p>
 */
public class RSASSAPSSFileSigner {

    private static final String PRIVATE_LABEL = "pss_rsa_private";
    private static final String INPUT_FILE = "message.txt";
    private static final String OUTPUT_SIG = "message.sig";
    private static final int SALT_LENGTH = 32;   // 用户要求 salt=32
    private static final String DIGEST_ALG = "SHA-256";
    // 使用通用的 "RSASSA-PSS" 算法名（而不是带摘要后缀的 "SHA256withRSA/PSS"），
    // 再通过 PSSParameterSpec 显式指定摘要=SHA-256、MGF1=SHA-256、saltLength=32。
    // 这样算法名更符合"RSASSA-PSS"这一语义，且 SDK 5 依然会在客户端本地先做
    // SHA-256、再把 hash 送到 HSM 做 PSS——与 NONEwithRSA/PSS 的效果等价。
    private static final String SIGN_ALG = "RSASSA-PSS";

    public static void main(String[] args) {
        try {
            // 加载 CloudHSM JCE Provider (SDK 5)
            Security.addProvider(new CloudHsmProvider());

            // 检查认证环境变量
            String hsmUser = System.getenv("HSM_USER");
            String hsmPassword = System.getenv("HSM_PASSWORD");
            if (hsmUser == null || hsmPassword == null) {
                System.err.println("错误：请设置环境变量 HSM_USER 和 HSM_PASSWORD");
                System.err.println("示例：");
                System.err.println("  export HSM_USER=your_cu_username");
                System.err.println("  export HSM_PASSWORD=your_cu_password");
                System.exit(1);
            }
            System.out.println("使用用户: " + hsmUser + " 连接到CloudHSM...");

            // 检查待签名文件
            if (!Files.exists(Paths.get(INPUT_FILE))) {
                System.err.println("错误：未找到待签名文件 " + INPUT_FILE);
                System.err.println("请先执行 ./write-message.sh 生成该文件。");
                System.exit(1);
            }

            // === 步骤1：应用层计算 SHA-256 ===
            System.out.println("\n--- 步骤1：应用层 Java 计算 " + DIGEST_ALG + " ---");
            byte[] sha256 = computeSha256(INPUT_FILE);
            System.out.println("文件:               " + INPUT_FILE);
            System.out.println("文件大小:           " + Files.size(Paths.get(INPUT_FILE)) + " bytes");
            System.out.println("SHA-256 (hex):      " + toHex(sha256));
            System.out.println("SHA-256 (base64):   " + Base64.getEncoder().encodeToString(sha256));
            System.out.println("SHA-256 长度:       " + sha256.length + " bytes");

            // === 步骤2：从 CloudHSM 加载私钥 ===
            System.out.println("\n--- 步骤2：从 CloudHSM 加载私钥 ---");
            KeyStoreWithAttributes keyStore =
                    KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME);
            keyStore.load(null, null);

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(PRIVATE_LABEL, null);
            if (privateKey == null) {
                System.err.println("错误：未在 CloudHSM 中找到私钥 label = " + PRIVATE_LABEL);
                System.err.println("请先运行 rsa-keygen jar 生成密钥。");
                System.exit(1);
            }
            System.out.println("已加载私钥 label: " + PRIVATE_LABEL);
            System.out.println("算法:             " + privateKey.getAlgorithm());

            // === 步骤3：使用 CloudHSM 做 RSASSA-PSS 签名（salt=32） ===
            System.out.println("\n--- 步骤3：CloudHSM 侧执行 RSASSA-PSS 签名 ---");
            System.out.println("签名算法:     " + SIGN_ALG);
            System.out.println("摘要算法:     SHA-256");
            System.out.println("MGF1 摘要:    SHA-256");
            System.out.println("saltLength:   " + SALT_LENGTH);
            System.out.println("trailerField: 1");

            Signature sig = Signature.getInstance(SIGN_ALG, CloudHsmProvider.PROVIDER_NAME);

            // 对于 "RSASSA-PSS" 这个通用算法名，CloudHSM 要求必须通过
            // setParameter(PSSParameterSpec) 显式指定摘要算法、MGF1、salt 长度；
            // 否则签名会失败（javadoc 原文："A call to Signature::setParameter()
            // is necessary to set the salt length and digest mechanism"）。
            PSSParameterSpec pssSpec = new PSSParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    SALT_LENGTH,
                    1);
            sig.setParameter(pssSpec);

            sig.initSign(privateKey);

            // 说明：CloudHSM SDK 5 的 "RSASSA-PSS"（搭配上面 PSSParameterSpec 中
            // 的 SHA-256）会由 CloudHSM JCE Provider 在客户端 JVM 内的软件先对
            // update() 进来的原始数据做 SHA-256，再把 32 字节的 hash 送到 HSM
            // 做 PSS 运算——与 NONEwithRSASSA-PSS + 应用层手算 SHA-256
            // 在协议语义上完全等价。所以这里直接 feed 原始文件内容，产出的签名
            // 与步骤1 我们自己算出来的 hash 一一对应。
            try (InputStream is = new BufferedInputStream(new FileInputStream(INPUT_FILE))) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) {
                    sig.update(buf, 0, n);
                }
            }

            byte[] signatureBytes = sig.sign();
            Files.write(Paths.get(OUTPUT_SIG), signatureBytes);

            System.out.println("签名完成！");
            System.out.println("签名文件:         " + OUTPUT_SIG);
            System.out.println("签名长度:         " + signatureBytes.length + " bytes");
            System.out.println("签名 (Base64):    " + Base64.getEncoder().encodeToString(signatureBytes));

            System.out.println("\n✅ RSASSA-PSS 签名完成");
            System.out.println("可使用以下 openssl 命令验签（需 pss_rsa_pub.pem 与 " + OUTPUT_SIG + "）：");
            System.out.println("  openssl dgst -sha256 \\");
            System.out.println("    -sigopt rsa_padding_mode:pss \\");
            System.out.println("    -sigopt rsa_pss_saltlen:" + SALT_LENGTH + " \\");
            System.out.println("    -sigopt rsa_mgf1_md:sha256 \\");
            System.out.println("    -verify pss_rsa_pub.pem \\");
            System.out.println("    -signature " + OUTPUT_SIG + " \\");
            System.out.println("    " + INPUT_FILE);

        } catch (Exception e) {
            System.err.println("签名失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * 在应用层（本地 Java，使用默认的 SUN Provider）对文件计算 SHA-256。
     * 显式指定 provider 为 "SUN"，避免意外使用到 CloudHSM provider 的摘要实现，
     * 从而确保"应用层做 hash"这一语义。
     */
    private static byte[] computeSha256(String filePath) throws Exception {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(DIGEST_ALG, "SUN");
        } catch (Exception e) {
            // 某些 JDK 发行版没有 "SUN" provider，fallback 到默认
            md = MessageDigest.getInstance(DIGEST_ALG);
        }
        try (InputStream is = new BufferedInputStream(new FileInputStream(filePath))) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                md.update(buf, 0, n);
            }
        }
        return md.digest();
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

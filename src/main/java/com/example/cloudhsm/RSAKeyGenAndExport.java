package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Base64;

/**
 * 在 CloudHSM 内生成 RSA-2048 非对称密钥对，并导出公钥 PEM 文件。
 *
 * 私钥以 label "pss_rsa_private" 永久保存在 CloudHSM 内，不可导出；
 * 公钥以 label "pss_rsa_public" 同时保存在 CloudHSM 内，并导出为
 * pss_rsa_pub.pem 供 openssl 做外部验签使用。
 *
 * 用法：
 *   export HSM_USER=&lt;CU用户名&gt;
 *   export HSM_PASSWORD=&lt;CU密码&gt;
 *   java -jar rsa-keygen-1.0-SNAPSHOT.jar
 */
public class RSAKeyGenAndExport {

    private static final String PRIVATE_LABEL = "pss_rsa_private";
    private static final String PUBLIC_LABEL = "pss_rsa_public";
    private static final String PUBLIC_PEM_FILE = "pss_rsa_pub.pem";
    private static final int RSA_KEY_SIZE = 2048;

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

            // === 步骤1：在 CloudHSM 内生成 RSA-2048 密钥对 ===
            System.out.println("\n--- 步骤1：在 CloudHSM 内生成 RSA-" + RSA_KEY_SIZE + " 密钥对 ---");
            KeyPairGenerator keyPairGen =
                    KeyPairGenerator.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME);

            KeyPairAttributesMap attrs = new KeyPairAttributesMap();

            // 公钥属性
            attrs.putPublic(KeyAttribute.LABEL, PUBLIC_LABEL);
            attrs.putPublic(KeyAttribute.TOKEN, true);                          // 持久化
            attrs.putPublic(KeyAttribute.VERIFY, true);                         // 可用于验签
            attrs.putPublic(KeyAttribute.MODULUS_BITS, RSA_KEY_SIZE);           // 2048 位
            attrs.putPublic(KeyAttribute.PUBLIC_EXPONENT,
                    RSAKeyGenParameterSpec.F4.toByteArray());                   // 公钥指数 65537

            // 私钥属性
            attrs.putPrivate(KeyAttribute.LABEL, PRIVATE_LABEL);
            attrs.putPrivate(KeyAttribute.TOKEN, true);                         // 持久化
            attrs.putPrivate(KeyAttribute.EXTRACTABLE, false);                  // 不可导出，更安全
            attrs.putPrivate(KeyAttribute.SIGN, true);                          // 可用于签名

            keyPairGen.initialize(attrs);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            System.out.println("RSA-" + RSA_KEY_SIZE + " 密钥对生成成功！");
            System.out.println("私钥 label: " + PRIVATE_LABEL);
            System.out.println("公钥 label: " + PUBLIC_LABEL);

            // === 步骤2：导出公钥 PEM ===
            System.out.println("\n--- 步骤2：导出公钥 PEM ---");
            PublicKey publicKey = keyPair.getPublic();
            byte[] pubEncoded = publicKey.getEncoded();  // X.509 SubjectPublicKeyInfo
            if (pubEncoded == null) {
                throw new IllegalStateException("公钥 getEncoded() 返回 null");
            }

            String pubPem = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pubEncoded)
                    + "\n-----END PUBLIC KEY-----\n";

            try (PrintWriter pw = new PrintWriter(new FileWriter(PUBLIC_PEM_FILE))) {
                pw.print(pubPem);
            }
            System.out.println("公钥 PEM 已保存到: " + PUBLIC_PEM_FILE);
            System.out.println("公钥算法:         " + publicKey.getAlgorithm());
            System.out.println("公钥格式:         " + publicKey.getFormat());
            System.out.println("公钥长度(bits):   " + RSA_KEY_SIZE);

            System.out.println("\n✅ 密钥生成和公钥导出完成");
            System.out.println("后续签名操作通过私钥 label \"" + PRIVATE_LABEL + "\" 引用私钥；");
            System.out.println("验签时使用公钥文件 " + PUBLIC_PEM_FILE + " 进行外部验证。");

        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}

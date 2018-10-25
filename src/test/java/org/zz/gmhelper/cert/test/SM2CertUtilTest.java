package org.zz.gmhelper.cert.test;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.SM2CertUtil;
import org.zz.gmhelper.test.GMBaseTest;
import org.zz.gmhelper.test.util.FileUtil;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class SM2CertUtilTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGetBCECPublicKey() {
        try {
            X509Certificate cert = SM2CertUtil.getX509Certificate("D:/test.sm2.cer");
            BCECPublicKey pubKey = SM2CertUtil.getBCECPublicKey(cert);
            byte[] priKeyData = FileUtil.readFile("D:/test.sm2.pri");
            ECPrivateKeyParameters priKeyParameters = BCECUtil.convertSEC1ToECPrivateKey(priKeyData);

            byte[] sign = SM2Util.sign(priKeyParameters, GMBaseTest.WITH_ID, GMBaseTest.SRC_DATA);
            System.out.println("SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));
            boolean flag = SM2Util.verify(pubKey, GMBaseTest.WITH_ID, GMBaseTest.SRC_DATA, sign);
            if (!flag) {
                Assert.fail("[withId] verify failed");
            }

            sign = SM2Util.sign(priKeyParameters, GMBaseTest.SRC_DATA);
            System.out.println("SM2 sign without withId result:\n" + ByteUtils.toHexString(sign));
            flag = SM2Util.verify(pubKey, GMBaseTest.SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

            byte[] cipherText = SM2Util.encrypt(pubKey, GMBaseTest.SRC_DATA);
            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(cipherText));
            byte[] plain = SM2Util.decrypt(priKeyParameters, cipherText);
            System.out.println("SM2 decrypt result:\n" + ByteUtils.toHexString(plain));
            if (!Arrays.equals(plain, GMBaseTest.SRC_DATA)) {
                Assert.fail("plain not equals the src");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}

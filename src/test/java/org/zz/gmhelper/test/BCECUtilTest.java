package org.zz.gmhelper.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;

public class BCECUtilTest {

    @Test
    public void testECPrivateKeyPKCS8() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKeyParams = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKeyParams = (ECPublicKeyParameters) keyPair.getPublic();
            byte[] pkcs8Bytes = BCECUtil.convertECPrivateKeyToPKCS8(priKeyParams, pubKeyParams);
            BCECPrivateKey priKey = BCECUtil.convertPKCS8ToECPrivateKey(pkcs8Bytes);

            byte[] sign = SM2Util.sign(priKey, GMBaseTest.WITH_ID, GMBaseTest.SRC_DATA);
            System.out.println("SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));
            boolean flag = SM2Util.verify(pubKeyParams, GMBaseTest.WITH_ID, GMBaseTest.SRC_DATA, sign);
            if (!flag) {
                Assert.fail("[withId] verify failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }
}

package org.zz.gmhelper.cert.test;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.SM2PrivateKey;
import org.zz.gmhelper.cert.SM2PublicKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SM2PrivateKeyTest {
    @Test
    public void testEncoded() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair keyPair = SM2Util.generateKeyPair();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
        SM2PublicKey sm2PublicKey = new SM2PublicKey(publicKey.getAlgorithm(), publicKey);
        SM2PrivateKey sm2PrivateKey1 = new SM2PrivateKey(privateKey, publicKey);
        SM2PrivateKey sm2PrivateKey2 = new SM2PrivateKey(privateKey, sm2PublicKey);
        String nativePriDER = ByteUtils.toHexString(privateKey.getEncoded());
        String sm2PriDER1 = ByteUtils.toHexString(sm2PrivateKey1.getEncoded());
        String sm2PriDER2 = ByteUtils.toHexString(sm2PrivateKey2.getEncoded());
        if (nativePriDER.equalsIgnoreCase(sm2PriDER1)) {
            Assert.fail();
        }
        if (!sm2PriDER1.equalsIgnoreCase(sm2PriDER2)) {
            Assert.fail();
        }
        System.out.println("Native EC Private Key DER:\n" + nativePriDER.toUpperCase());
        System.out.println("SM2 EC Private Key DER:\n" + sm2PriDER1.toUpperCase());
    }
}

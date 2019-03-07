package org.zz.gmhelper.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM2PreprocessSigner;
import org.zz.gmhelper.SM2Util;

import java.security.SecureRandom;
import java.util.Arrays;

public class SM2PreprocessSignerTest extends GMBaseTest {

    @Test
    public void test() throws CryptoException {
        AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
        ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

        SM2PreprocessSigner signer = new SM2PreprocessSigner();
        CipherParameters pwr = new ParametersWithRandom(priKey, new SecureRandom());
        signer.init(true, pwr);
        byte[] eHash1 = signer.preprocess(SRC_DATA, 0, SRC_DATA.length);
        byte[] sign1 = signer.generateSignature(eHash1);

        signer = new SM2PreprocessSigner();
        signer.init(false, pubKey);
        byte[] eHash2 = signer.preprocess(SRC_DATA, 0, SRC_DATA.length);
        if (!Arrays.equals(eHash1, eHash2)) {
            Assert.fail();
        }
        if (!signer.verifySignature(eHash1, sign1)) {
            Assert.fail();
        }
    }
}

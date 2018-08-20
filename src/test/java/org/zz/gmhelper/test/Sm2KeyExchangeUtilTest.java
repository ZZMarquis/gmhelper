package org.zz.gmhelper.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.Sm2KeyExchangeUtil;
import org.zz.gmhelper.Sm2Util;

import java.util.Arrays;

public class Sm2KeyExchangeUtilTest {
    private static final byte[] INITIATOR_ID = "ABCDEFG1234".getBytes();
    private static final byte[] RESPONDER_ID = "1234567ABCD".getBytes();
    private static final int KEY_BITS = 128;

    @Test
    public void TestCaculateKey() {
        try {
            AsymmetricCipherKeyPair initiatorStaticKp = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters initiatorStaticPriv = (ECPrivateKeyParameters) initiatorStaticKp.getPrivate();
            ECPublicKeyParameters initiatorStaticPub = (ECPublicKeyParameters) initiatorStaticKp.getPublic();
            AsymmetricCipherKeyPair initiatorEphemeralKp = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters initiatorEphemeralPriv = (ECPrivateKeyParameters) initiatorEphemeralKp.getPrivate();
            ECPublicKeyParameters initiatorSEphemeralPub = (ECPublicKeyParameters) initiatorEphemeralKp.getPublic();
            AsymmetricCipherKeyPair responderStaticKp = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters responderStaticPriv = (ECPrivateKeyParameters) responderStaticKp.getPrivate();
            ECPublicKeyParameters responderStaticPub = (ECPublicKeyParameters) responderStaticKp.getPublic();
            AsymmetricCipherKeyPair responderEphemeralKp = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters responderEphemeralPriv = (ECPrivateKeyParameters) responderEphemeralKp.getPrivate();
            ECPublicKeyParameters responderSEphemeralPub = (ECPublicKeyParameters) responderEphemeralKp.getPublic();

            //实际应用中应该是通过网络交换临时公钥
            byte[] k1 = Sm2KeyExchangeUtil.caculateKey(true, KEY_BITS,
                initiatorStaticPriv, initiatorEphemeralPriv, INITIATOR_ID,
                responderStaticPub, responderSEphemeralPub, RESPONDER_ID);
            byte[] k2 = Sm2KeyExchangeUtil.caculateKey(false, KEY_BITS,
                responderStaticPriv, responderEphemeralPriv, RESPONDER_ID,
                initiatorStaticPub, initiatorSEphemeralPub, INITIATOR_ID);

            if (!Arrays.equals(k1, k2)) {
                Assert.assertTrue(false);
            }
        } catch (Exception ex) {
            Assert.assertTrue(false);
        }
    }

    @Test
    public void TestCalculateKeyWithConfirmation() {
        try {
            AsymmetricCipherKeyPair initiatorStaticKp = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters initiatorStaticPriv = (ECPrivateKeyParameters) initiatorStaticKp.getPrivate();
            ECPublicKeyParameters initiatorStaticPub = (ECPublicKeyParameters) initiatorStaticKp.getPublic();
            AsymmetricCipherKeyPair initiatorEphemeralKp = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters initiatorEphemeralPriv = (ECPrivateKeyParameters) initiatorEphemeralKp.getPrivate();
            ECPublicKeyParameters initiatorSEphemeralPub = (ECPublicKeyParameters) initiatorEphemeralKp.getPublic();
            AsymmetricCipherKeyPair responderStaticKp = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters responderStaticPriv = (ECPrivateKeyParameters) responderStaticKp.getPrivate();
            ECPublicKeyParameters responderStaticPub = (ECPublicKeyParameters) responderStaticKp.getPublic();
            AsymmetricCipherKeyPair responderEphemeralKp = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters responderEphemeralPriv = (ECPrivateKeyParameters) responderEphemeralKp.getPrivate();
            ECPublicKeyParameters responderSEphemeralPub = (ECPublicKeyParameters) responderEphemeralKp.getPublic();

            //第一步应该是交换临时公钥等信息

            //第二步响应方生成密钥和验证信息
            Sm2KeyExchangeUtil.ExchangeResult responderResult = Sm2KeyExchangeUtil.calculateKeyWithConfirmation(
                false, KEY_BITS, null,
                responderStaticPriv, responderEphemeralPriv, RESPONDER_ID,
                initiatorStaticPub, initiatorSEphemeralPub, INITIATOR_ID);

            //第三步发起方生成密钥和验证消息，并验证响应方的验证消息
            Sm2KeyExchangeUtil.ExchangeResult initiatorResult = Sm2KeyExchangeUtil.calculateKeyWithConfirmation(
                true, KEY_BITS, responderResult.getS1(),
                initiatorStaticPriv, initiatorEphemeralPriv, INITIATOR_ID,
                responderStaticPub, responderSEphemeralPub, RESPONDER_ID);

            //第四步响应方验证发起方的验证消息
            if (!Sm2KeyExchangeUtil.responderConfirm(responderResult.getS2(), initiatorResult.getS2())) {
                Assert.assertTrue(false);
            }
        } catch (Exception ex) {
            Assert.assertTrue(false);
        }
    }
}

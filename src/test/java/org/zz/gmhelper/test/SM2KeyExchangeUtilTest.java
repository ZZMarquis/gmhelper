package org.zz.gmhelper.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM2KeyExchangeUtil;
import org.zz.gmhelper.SM2Util;

import java.util.Arrays;

public class SM2KeyExchangeUtilTest {
  private static final byte[] INITIATOR_ID = "ABCDEFG1234".getBytes();
  private static final byte[] RESPONDER_ID = "1234567ABCD".getBytes();
  private static final int KEY_BITS = 128;

  @Test
  public void testCaculateKey() {
    try {
      AsymmetricCipherKeyPair initiatorStaticKp = SM2Util.generateKeyPair();
      ECPrivateKeyParameters initiatorStaticPriv =
          (ECPrivateKeyParameters) initiatorStaticKp.getPrivate();
      ECPublicKeyParameters initiatorStaticPub =
          (ECPublicKeyParameters) initiatorStaticKp.getPublic();
      AsymmetricCipherKeyPair initiatorEphemeralKp = SM2Util.generateKeyPair();
      ECPrivateKeyParameters initiatorEphemeralPriv =
          (ECPrivateKeyParameters) initiatorEphemeralKp.getPrivate();
      ECPublicKeyParameters initiatorSEphemeralPub =
          (ECPublicKeyParameters) initiatorEphemeralKp.getPublic();
      AsymmetricCipherKeyPair responderStaticKp = SM2Util.generateKeyPair();
      ECPrivateKeyParameters responderStaticPriv =
          (ECPrivateKeyParameters) responderStaticKp.getPrivate();
      ECPublicKeyParameters responderStaticPub =
          (ECPublicKeyParameters) responderStaticKp.getPublic();
      AsymmetricCipherKeyPair responderEphemeralKp = SM2Util.generateKeyPair();
      ECPrivateKeyParameters responderEphemeralPriv =
          (ECPrivateKeyParameters) responderEphemeralKp.getPrivate();
      ECPublicKeyParameters responderSEphemeralPub =
          (ECPublicKeyParameters) responderEphemeralKp.getPublic();

      // 实际应用中应该是通过网络交换临时公钥
      byte[] k1 =
          SM2KeyExchangeUtil.calculateKey(
              true,
              SM2KeyExchangeUtilTest.KEY_BITS,
              initiatorStaticPriv,
              initiatorEphemeralPriv,
              SM2KeyExchangeUtilTest.INITIATOR_ID,
              responderStaticPub,
              responderSEphemeralPub,
              SM2KeyExchangeUtilTest.RESPONDER_ID);
      byte[] k2 =
          SM2KeyExchangeUtil.calculateKey(
              false,
              SM2KeyExchangeUtilTest.KEY_BITS,
              responderStaticPriv,
              responderEphemeralPriv,
              SM2KeyExchangeUtilTest.RESPONDER_ID,
              initiatorStaticPub,
              initiatorSEphemeralPub,
              SM2KeyExchangeUtilTest.INITIATOR_ID);

      if (!Arrays.equals(k1, k2)) {
        Assert.fail();
      }
    } catch (Exception ex) {
      Assert.fail();
    }
  }

  @Test
  public void testCalculateKeyWithConfirmation() {
    try {
      AsymmetricCipherKeyPair initiatorStaticKp = SM2Util.generateKeyPair();
      ECPrivateKeyParameters initiatorStaticPriv =
          (ECPrivateKeyParameters) initiatorStaticKp.getPrivate();
      ECPublicKeyParameters initiatorStaticPub =
          (ECPublicKeyParameters) initiatorStaticKp.getPublic();
      AsymmetricCipherKeyPair initiatorEphemeralKp = SM2Util.generateKeyPair();
      ECPrivateKeyParameters initiatorEphemeralPriv =
          (ECPrivateKeyParameters) initiatorEphemeralKp.getPrivate();
      ECPublicKeyParameters initiatorSEphemeralPub =
          (ECPublicKeyParameters) initiatorEphemeralKp.getPublic();
      AsymmetricCipherKeyPair responderStaticKp = SM2Util.generateKeyPair();
      ECPrivateKeyParameters responderStaticPriv =
          (ECPrivateKeyParameters) responderStaticKp.getPrivate();
      ECPublicKeyParameters responderStaticPub =
          (ECPublicKeyParameters) responderStaticKp.getPublic();
      AsymmetricCipherKeyPair responderEphemeralKp = SM2Util.generateKeyPair();
      ECPrivateKeyParameters responderEphemeralPriv =
          (ECPrivateKeyParameters) responderEphemeralKp.getPrivate();
      ECPublicKeyParameters responderSEphemeralPub =
          (ECPublicKeyParameters) responderEphemeralKp.getPublic();

      // 第一步应该是交换临时公钥等信息

      // 第二步响应方生成密钥和验证信息
      SM2KeyExchangeUtil.ExchangeResult responderResult =
          SM2KeyExchangeUtil.calculateKeyWithConfirmation(
              false,
              SM2KeyExchangeUtilTest.KEY_BITS,
              null,
              responderStaticPriv,
              responderEphemeralPriv,
              SM2KeyExchangeUtilTest.RESPONDER_ID,
              initiatorStaticPub,
              initiatorSEphemeralPub,
              SM2KeyExchangeUtilTest.INITIATOR_ID);

      // 第三步发起方生成密钥和验证消息，并验证响应方的验证消息
      SM2KeyExchangeUtil.ExchangeResult initiatorResult =
          SM2KeyExchangeUtil.calculateKeyWithConfirmation(
              true,
              SM2KeyExchangeUtilTest.KEY_BITS,
              responderResult.getS1(),
              initiatorStaticPriv,
              initiatorEphemeralPriv,
              SM2KeyExchangeUtilTest.INITIATOR_ID,
              responderStaticPub,
              responderSEphemeralPub,
              SM2KeyExchangeUtilTest.RESPONDER_ID);

      // 第四步响应方验证发起方的验证消息
      if (!SM2KeyExchangeUtil.responderConfirm(responderResult.getS2(), initiatorResult.getS2())) {
        Assert.fail();
      }
    } catch (Exception ex) {
      Assert.fail();
    }
  }
}

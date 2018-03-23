package org.zz.gmhelper.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.Sm2Util;

import java.util.Arrays;

public class Sm2UtilTest extends GmBaseTest {
  
  @Test
  public void testSignAndVerify() {
    try {
      AsymmetricCipherKeyPair keyPair = Sm2Util.generateKeyPair();
      ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
      ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();
      
      byte[] sign = Sm2Util.sign(priKey, WITH_ID, SRC_DATA);
      System.out.println("SM2 sign with withId result:\n" + Arrays.toString(sign));
      boolean flag = Sm2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
      if (!flag) {
        Assert.assertTrue(false);
      }
      
      sign = Sm2Util.sign(priKey, SRC_DATA);
      System.out.println("SM2 sign without withId result:\n" + Arrays.toString(sign));
      flag = Sm2Util.verify(pubKey, SRC_DATA, sign);
      if (!flag) {
        Assert.assertTrue(false);
      }
      Assert.assertTrue(true);
    } catch (Exception ex) {
      ex.printStackTrace();
      Assert.assertTrue(false);
    }
  }
  
  @Test
  public void testEncryptAndDecrypt() {
    try {
      AsymmetricCipherKeyPair keyPair = Sm2Util.generateKeyPair();
      ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
      ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();
      
      byte[] encryptedData = Sm2Util.encryt(pubKey, SRC_DATA);
      System.out.println("SM2 encrypt result:\n" + Arrays.toString(encryptedData));
      byte[] decryptedData = Sm2Util.decrypt(priKey, encryptedData);
      System.out.println("SM2 decrypt result:\n" + Arrays.toString(decryptedData));
      if (!Arrays.equals(decryptedData, SRC_DATA)) {
        Assert.assertTrue(false);
      }
      Assert.assertTrue(true);
    } catch (Exception ex) {
      ex.printStackTrace();
      Assert.assertTrue(false);
    }
  }
}

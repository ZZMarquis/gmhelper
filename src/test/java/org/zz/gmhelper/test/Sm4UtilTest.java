package org.zz.gmhelper.test;

import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.Sm4Util;

import java.util.Arrays;

public class Sm4UtilTest extends GmBaseTest {
  
  @Test
  public void testEncryptAndDecrypt() {
    try {
      byte[] key = Sm4Util.generateKey();
      byte[] iv = Sm4Util.generateKey();
      byte[] cipherText = null;
      byte[] decryptedData = null;
      
      cipherText = Sm4Util.encrypt_Ecb_Padding(key, SRC_DATA);
      System.out.println("SM4 ECB Padding encrypt result:\n" + Arrays.toString(cipherText));
      decryptedData = Sm4Util.decrypt_Ecb_Padding(key, cipherText);
      System.out.println("SM4 ECB Padding decrypt result:\n" + Arrays.toString(decryptedData));
      if (!Arrays.equals(decryptedData, SRC_DATA)) {
        Assert.assertTrue(false);
      }
      
      cipherText = Sm4Util.encrypt_Cbc_Padding(key, iv, SRC_DATA);
      System.out.println("SM4 CBC Padding encrypt result:\n" + Arrays.toString(cipherText));
      decryptedData = Sm4Util.decrypt_Cbc_Padding(key, iv, cipherText);
      System.out.println("SM4 CBC Padding decrypt result:\n" + Arrays.toString(decryptedData));
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

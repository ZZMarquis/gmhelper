package org.zz.gmhelper.test;

import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM4Util;

import java.util.Arrays;

public class SM4UtilTest extends GMBaseTest {

    @Test
    public void testEncryptAndDecrypt() {
        try {
            byte[] key = SM4Util.generateKey();
            byte[] iv = SM4Util.generateKey();
            byte[] cipherText = null;
            byte[] decryptedData = null;

            cipherText = SM4Util.encrypt_Ecb_Padding(key, SRC_DATA);
            System.out.println("SM4 ECB Padding encrypt result:\n" + Arrays.toString(cipherText));
            decryptedData = SM4Util.decrypt_Ecb_Padding(key, cipherText);
            System.out.println("SM4 ECB Padding decrypt result:\n" + Arrays.toString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            cipherText = SM4Util.encrypt_Cbc_Padding(key, iv, SRC_DATA);
            System.out.println("SM4 CBC Padding encrypt result:\n" + Arrays.toString(cipherText));
            decryptedData = SM4Util.decrypt_Cbc_Padding(key, iv, cipherText);
            System.out.println("SM4 CBC Padding decrypt result:\n" + Arrays.toString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}

package org.zz.gmhelper.test;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.Sm3Util;

public class Sm3UtilTest extends GmBaseTest {
    @Test
    public void testHashAndVerify() {
        try {
            byte[] hash = Sm3Util.hash(SRC_DATA);
            System.out.println("SM3 hash result:\n" + Arrays.toString(hash));
            boolean flag = Sm3Util.verify(SRC_DATA, hash);
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
    public void testHmacSm3() {
        try {
            byte[] hmacKey = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
            byte[] hmac = Sm3Util.hmac(hmacKey, SRC_DATA);
            System.out.println("SM3 hash result:\n" + Arrays.toString(hmac));
            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.assertTrue(false);
        }
    }
}

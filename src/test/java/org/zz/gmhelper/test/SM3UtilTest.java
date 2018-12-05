package org.zz.gmhelper.test;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM3Util;

import java.util.Arrays;

public class SM3UtilTest extends GMBaseTest {
    @Test
    public void testHashAndVerify() {
        try {
            byte[] hash = SM3Util.hash(SRC_DATA);
            System.out.println("SM3 hash result:\n" + ByteUtils.toHexString(hash));
            boolean flag = SM3Util.verify(SRC_DATA, hash);
            if (!flag) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testHmacSM3() {
        try {
            byte[] hmacKey = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
            byte[] hmac = SM3Util.hmac(hmacKey, SRC_DATA);
            System.out.println("SM3 hash result:\n" + Arrays.toString(hmac));
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}

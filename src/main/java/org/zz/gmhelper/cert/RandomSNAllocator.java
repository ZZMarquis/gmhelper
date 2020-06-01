/*
 *
 * This is simplified version of the RandomSerialNumberGenerator from the project
 * https://github.com/xipki/xipki.
 */

package org.zz.gmhelper.cert;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Random serial number generator.
 * 
 * This class is thread safe.
 *
 * @author Lijun Liao
 */
public class RandomSNAllocator implements CertSNAllocator {

    /**
     * The highest bit is always set to 1, so the effective bit length is bitLen - 1. To ensure that
     * at least 64 bit entropy, bitLen must be at least 65.
     */
    private final static int MIN_SERIALNUMBER_SIZE = 65;

    /**
     * Since serial number should be positive and maximal 20 bytes, the maximal value of bitLen is
     * 159.
     */
    private final static int MAX_SERIALNUMBER_SIZE = 159;

    private static int[] AND_MASKS = new int[] {0xFF, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F};

    private static int[]  OR_MASKS = new int[] {0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};

    private final SecureRandom random;
  
    private final int bitLen;

    /**
     * Constructor with the bitLen = 65.
     */
    public RandomSNAllocator() {
        this(MIN_SERIALNUMBER_SIZE);
    }

    /**
     * Constructor with the specification of bitLen.
     * @param bitLen bit length of the serial number. The highest bit is always set to 1, so the
     *        effective bit length is bitLen - 1. Valid value is [65, 159].
     */
    public RandomSNAllocator(int bitLen) {
        if (bitLen < MIN_SERIALNUMBER_SIZE || bitLen > MAX_SERIALNUMBER_SIZE) {
            throw new IllegalArgumentException(String.format(
                "%s may not be out of the range [%d, %d]: %d",
                "bitLen", MIN_SERIALNUMBER_SIZE, MAX_SERIALNUMBER_SIZE, bitLen));
        }

        this.random = new SecureRandom();
        this.bitLen = bitLen;
    }

    @Override
    public BigInteger nextSerialNumber() {
        final byte[] rdnBytes = new byte[(bitLen + 7) / 8];
        final int ci = bitLen % 8;

        random.nextBytes(rdnBytes);
        if (ci != 0) {
            rdnBytes[0] = (byte) (rdnBytes[0] & AND_MASKS[ci]);
        }
        rdnBytes[0] = (byte) (rdnBytes[0] | OR_MASKS[ci]);

        return new BigInteger(1, rdnBytes);
    }
  
}

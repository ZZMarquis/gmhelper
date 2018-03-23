package org.zz.gmhelper;

import org.bouncycastle.crypto.digests.SM3Digest;

import java.util.Arrays;

public class Sm3Util extends GmBaseUtil {
  
  public static byte[] hash(byte[] srcData) {
    SM3Digest digest = new SM3Digest();
    digest.update(srcData, 0, srcData.length);
    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);
    return hash;
  }

  public static boolean verify(byte[] srcData, byte[] sm3Hash) {
    byte[] newHash = hash(srcData);
    if (Arrays.equals(newHash, sm3Hash)) {
      return true;
    } else {
      return false;
    }
  }
}

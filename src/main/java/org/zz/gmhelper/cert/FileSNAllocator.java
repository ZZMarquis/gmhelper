package org.zz.gmhelper.cert;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;

public class FileSNAllocator implements CertSNAllocator {
  private static final String SN_FILENAME = "sn.dat";
  private static final String snFilePath;

  static {
    ClassLoader loader = FileSNAllocator.class.getClassLoader();
    snFilePath = loader.getResource(FileSNAllocator.SN_FILENAME).getPath();
  }

  private static BigInteger readSN() throws IOException {
    RandomAccessFile raf = null;
    try {
      raf = new RandomAccessFile(FileSNAllocator.snFilePath, "r");
      byte[] data = new byte[(int) raf.length()];
      raf.read(data);
      String snStr = new String(data);
      return new BigInteger(snStr);
    } finally {
      if (raf != null) {
        raf.close();
      }
    }
  }

  private static void writeSN(BigInteger sn) throws IOException {
    RandomAccessFile raf = null;
    try {
      raf = new RandomAccessFile(FileSNAllocator.snFilePath, "rw");
      raf.writeBytes(sn.toString(10));
    } finally {
      if (raf != null) {
        raf.close();
      }
    }
  }

  @Override
  public synchronized BigInteger incrementAndGet() throws Exception {
    BigInteger sn = FileSNAllocator.readSN();
    FileSNAllocator.writeSN(sn.add(BigInteger.ONE));
    return sn;
  }
}

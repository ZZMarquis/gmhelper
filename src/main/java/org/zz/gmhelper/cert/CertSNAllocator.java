package org.zz.gmhelper.cert;

import java.math.BigInteger;

public interface CertSNAllocator {
    BigInteger incrementAndGet() throws Exception;
}

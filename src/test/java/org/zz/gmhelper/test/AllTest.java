package org.zz.gmhelper.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
import org.zz.gmhelper.cert.test.FileSNAllocatorTest;
import org.zz.gmhelper.cert.test.SM2CertUtilTest;
import org.zz.gmhelper.cert.test.SM2PfxMakerTest;
import org.zz.gmhelper.cert.test.SM2PrivateKeyTest;
import org.zz.gmhelper.cert.test.SM2X509CertMakerTest;

@RunWith(Suite.class)
@SuiteClasses({BCECUtilTest.class, SM2UtilTest.class, SM3UtilTest.class, SM4UtilTest.class,
    SM2KeyExchangeUtilTest.class, SM2PreprocessSignerTest.class,
    // ------------------------------------
    FileSNAllocatorTest.class, SM2CertUtilTest.class, SM2PfxMakerTest.class, SM2PrivateKeyTest.class,
    SM2X509CertMakerTest.class})
public class AllTest {
}

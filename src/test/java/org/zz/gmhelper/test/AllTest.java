package org.zz.gmhelper.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({SM2UtilTest.class, SM3UtilTest.class, SM4UtilTest.class, SM2KeyExchangeUtilTest.class})
public class AllTest {
}

package org.zz.gmhelper;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GmBaseUtil {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}

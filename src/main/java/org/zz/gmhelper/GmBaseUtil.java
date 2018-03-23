package org.zz.gmhelper;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class GmBaseUtil {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }
}

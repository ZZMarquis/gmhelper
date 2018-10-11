package org.zz.gmhelper.cert.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.Sm2Util;
import org.zz.gmhelper.cert.PKIUtil;
import org.zz.gmhelper.cert.X509CertificateMaker;
import org.zz.gmhelper.test.util.FileUtil;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

public class X509CertificateMakerTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMakeCertificate() {
        try {
            KeyPair issKP = Sm2Util.generateBCECKeyPair();
            KeyPair subKP = Sm2Util.generateBCECKeyPair();
            X500Name subDN = buildSubjectDN();
            byte[] csr = PKIUtil.createCSR(subDN, subKP.getPublic(), subKP.getPrivate()).getEncoded();
            X509Certificate cert = X509CertificateMaker.makeCertificate(issKP, false, csr);
            FileUtil.writeFile("D:/test.cer", cert.getEncoded());
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.assertTrue(false);
        }
    }

    private X500Name buildSubjectDN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, "zz");
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        return builder.build();
    }
}

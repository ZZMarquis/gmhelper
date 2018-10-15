package org.zz.gmhelper.cert.test;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.Sm2Util;
import org.zz.gmhelper.cert.CommonUtil;
import org.zz.gmhelper.cert.Sm2PfxMaker;
import org.zz.gmhelper.cert.Sm2X509CertMaker;
import org.zz.gmhelper.test.util.FileUtil;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

public class Sm2PfxMakerTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMakePfx() {
        try {
            KeyPair subKP = Sm2Util.generateBCECKeyPair();
            X500Name subDN = Sm2CertMakerTest.buildSubjectDN();
            byte[] csr = CommonUtil.createCSR(subDN, subKP.getPublic(), subKP.getPrivate(),
                Sm2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            Sm2X509CertMaker certMaker = Sm2CertMakerTest.buildCertMaker();
            X509Certificate cert = certMaker.makeCertificate(false,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment), csr);

            Sm2PfxMaker pfxMaker = new Sm2PfxMaker();
            PKCS12PfxPdu pfx = pfxMaker.makePfx(subKP.getPrivate(), subKP.getPublic(), cert, "12345678");
            byte[] pfxDER = pfx.getEncoded(ASN1Encoding.DER);
            FileUtil.writeFile("D:/test.pfx", pfxDER);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}

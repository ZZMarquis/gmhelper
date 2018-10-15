package org.zz.gmhelper.cert.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.Sm2Util;
import org.zz.gmhelper.cert.CertSNAllocator;
import org.zz.gmhelper.cert.CommonUtil;
import org.zz.gmhelper.cert.FileSNAllocator;
import org.zz.gmhelper.cert.Sm2X509CertMaker;
import org.zz.gmhelper.cert.exception.InvalidX500NameException;
import org.zz.gmhelper.test.util.FileUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class Sm2CertMakerTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMakeCertificate() {
        try {
            KeyPair subKP = Sm2Util.generateBCECKeyPair();
            X500Name subDN = buildSubjectDN();
            byte[] csr = CommonUtil.createCSR(subDN, subKP.getPublic(), subKP.getPrivate(),
                Sm2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            Sm2X509CertMaker certMaker = buildCertMaker();
            X509Certificate cert = certMaker.makeCertificate(false,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment), csr);
            FileUtil.writeFile("D:/test.cer", cert.getEncoded());
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
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

    private Sm2X509CertMaker buildCertMaker() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidX500NameException {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, "ZZ Root CA");
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        X500Name issuerName = builder.build();
        KeyPair issKP = Sm2Util.generateBCECKeyPair();
        long certExpire = 20L * 365 * 24 * 60 * 60 * 1000; // 20年
        CertSNAllocator snAllocator = new FileSNAllocator(); // 实际应用中可能需要使用数据库来维护证书序列号
        return new Sm2X509CertMaker(issKP, certExpire, issuerName, snAllocator);
    }
}

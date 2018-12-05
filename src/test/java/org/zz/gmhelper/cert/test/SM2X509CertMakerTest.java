package org.zz.gmhelper.cert.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.CertSNAllocator;
import org.zz.gmhelper.cert.CommonUtil;
import org.zz.gmhelper.cert.FileSNAllocator;
import org.zz.gmhelper.cert.SM2PublicKey;
import org.zz.gmhelper.cert.SM2X509CertMaker;
import org.zz.gmhelper.cert.exception.InvalidX500NameException;
import org.zz.gmhelper.test.util.FileUtil;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;

public class SM2X509CertMakerTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMakeCertificate() {
        try {
            KeyPair subKP = SM2Util.generateBCECKeyPair();
            X500Name subDN = buildSubjectDN();
            SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
                (BCECPublicKey) subKP.getPublic());
            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            savePriKey("D://test.sm2.pri", (BCECPrivateKey) subKP.getPrivate(),
                (BCECPublicKey) subKP.getPublic());
            SM2X509CertMaker certMaker = buildCertMaker();
            X509Certificate cert = certMaker.makeCertificate(false,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment), csr);
            FileUtil.writeFile("D:/test.sm2.cer", cert.getEncoded());
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    public static void savePriKey(String filePath, BCECPrivateKey priKey, BCECPublicKey pubKey) throws IOException {
        ECPrivateKeyParameters priKeyParam = SM2Util.convertPrivateKey(priKey);
        ECPublicKeyParameters pubKeyParam = SM2Util.convertPublicKey(pubKey);
        byte[] derPriKey = BCECUtil.convertECPrivateKeyToSEC1(priKeyParam, pubKeyParam);
        FileUtil.writeFile(filePath, derPriKey);
    }

    public static X500Name buildSubjectDN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, "zz");
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        return builder.build();
    }

    public static X500Name buildRootCADN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, "ZZ Root CA");
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        return builder.build();
    }

    public static SM2X509CertMaker buildCertMaker() throws InvalidAlgorithmParameterException,
        NoSuchAlgorithmException, NoSuchProviderException, InvalidX500NameException {
        X500Name issuerName = buildRootCADN();
        KeyPair issKP = SM2Util.generateBCECKeyPair();
        long certExpire = 20L * 365 * 24 * 60 * 60 * 1000; // 20年
        CertSNAllocator snAllocator = new FileSNAllocator(); // 实际应用中可能需要使用数据库来维护证书序列号
        return new SM2X509CertMaker(issKP, certExpire, issuerName, snAllocator);
    }
}

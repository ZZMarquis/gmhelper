package org.zz.gmhelper.cert.test;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.CommonUtil;
import org.zz.gmhelper.cert.SM2Pkcs12Maker;
import org.zz.gmhelper.cert.SM2PublicKey;
import org.zz.gmhelper.cert.SM2X509CertMaker;

/**
 * @author Lijun Liao https:/github.com/xipki
 */
public class SM2Pkcs12MakerTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final char[] TEST_P12_PASSWD = "12345678".toCharArray();
    private static final String TEST_P12_FILENAME = "target/test.p12";

    @Test
    public void testMakePkcs12() {
        try {
            KeyPair subKP = SM2Util.generateKeyPair();
            X500Name subDN = SM2X509CertMakerTest.buildSubjectDN();
            SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
                (BCECPublicKey) subKP.getPublic());
            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            SM2X509CertMaker certMaker = SM2X509CertMakerTest.buildCertMaker();
            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);

            SM2Pkcs12Maker pkcs12Maker = new SM2Pkcs12Maker();
            KeyStore pkcs12 = pkcs12Maker.makePkcs12(subKP.getPrivate(), cert, TEST_P12_PASSWD);
            try (OutputStream os = Files.newOutputStream(Paths.get(TEST_P12_FILENAME),
                                        StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                pkcs12.store(os, TEST_P12_PASSWD);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testPkcs12Sign() {
        //先生成一个pkcs12
        testMakePkcs12();

        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            try (InputStream is = Files.newInputStream(Paths.get(TEST_P12_FILENAME),
                                      StandardOpenOption.READ)) {
                ks.load(is, TEST_P12_PASSWD);
            }

            PrivateKey privateKey = (BCECPrivateKey) ks.getKey("User Key", TEST_P12_PASSWD);
            X509Certificate cert = (X509Certificate) ks.getCertificate("User Key");

            byte[] srcData = "1234567890123456789012345678901234567890".getBytes();

            // create signature
            Signature sign = Signature.getInstance(SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2, "BC");
            sign.initSign(privateKey);
            sign.update(srcData);
            byte[] signatureValue = sign.sign();

            // verify signature
            Signature verify = Signature.getInstance(SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2, "BC");
            verify.initVerify(cert);
            verify.update(srcData);
            boolean sigValid = verify.verify(signatureValue);
            Assert.assertTrue("signature validation result", sigValid);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}

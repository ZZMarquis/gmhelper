package org.zz.gmhelper.cert.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.CertSNAllocator;
import org.zz.gmhelper.cert.CommonUtil;
import org.zz.gmhelper.cert.RandomSNAllocator;
import org.zz.gmhelper.cert.SM2CertUtil;
import org.zz.gmhelper.cert.SM2PublicKey;
import org.zz.gmhelper.cert.SM2X509CertMaker;
import org.zz.gmhelper.test.GMBaseTest;
import org.zz.gmhelper.test.util.FileUtil;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class SM2CertUtilTest {
    private static final String ROOT_PRI_PATH = "target/test.root.ca.pri";
    private static final String ROOT_CERT_PATH = "target/test.root.ca.cer";
    private static final String MID_PRI_PATH = "target/test.mid.ca.pri";
    private static final String MID_CERT_PATH = "target/test.mid.ca.cer";
    private static final String USER_PRI_PATH = "target/test.user.pri";
    private static final String USER_CERT_PATH = "target/test.user.cer";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGetBCECPublicKey() {
        try {
            //当前测试例依赖以下测试例生成的文件，所以先调用一下
            new SM2X509CertMakerTest().testMakeCertificate();

            X509Certificate cert = SM2CertUtil.getX509Certificate("target/test.sm2.cer");
            BCECPublicKey pubKey = SM2CertUtil.getBCECPublicKey(cert);
            byte[] priKeyData = FileUtil.readFile("target/test.sm2.pri");
            ECPrivateKeyParameters priKeyParameters = BCECUtil.convertSEC1ToECPrivateKey(priKeyData);

            byte[] sign = SM2Util.sign(priKeyParameters, GMBaseTest.WITH_ID, GMBaseTest.SRC_DATA);
            System.out.println("SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));
            boolean flag = SM2Util.verify(pubKey, GMBaseTest.WITH_ID, GMBaseTest.SRC_DATA, sign);
            if (!flag) {
                Assert.fail("[withId] verify failed");
            }

            sign = SM2Util.sign(priKeyParameters, GMBaseTest.SRC_DATA);
            System.out.println("SM2 sign without withId result:\n" + ByteUtils.toHexString(sign));
            flag = SM2Util.verify(pubKey, GMBaseTest.SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

            byte[] cipherText = SM2Util.encrypt(pubKey, GMBaseTest.SRC_DATA);
            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(cipherText));
            byte[] plain = SM2Util.decrypt(priKeyParameters, cipherText);
            System.out.println("SM2 decrypt result:\n" + ByteUtils.toHexString(plain));
            if (!Arrays.equals(plain, GMBaseTest.SRC_DATA)) {
                Assert.fail("plain not equals the src");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testVerifyCertificate() {
        try {
            long certExpire = 20L * 365 * 24 * 60 * 60 * 1000;
            CertSNAllocator snAllocator = new RandomSNAllocator();
            KeyPair rootKP = SM2Util.generateKeyPair();
            X500Name rootDN = SM2X509CertMakerTest.buildRootCADN();
            SM2X509CertMaker rootCertMaker = new SM2X509CertMaker(rootKP, certExpire, rootDN, snAllocator);
            SM2PublicKey rootPub = new SM2PublicKey(rootKP.getPublic().getAlgorithm(),
                (BCECPublicKey) rootKP.getPublic());
            byte[] rootCSR = CommonUtil.createCSR(rootDN, rootPub, rootKP.getPrivate(),
                SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            SM2X509CertMakerTest.savePriKey(ROOT_PRI_PATH, (BCECPrivateKey) rootKP.getPrivate(),
                (BCECPublicKey) rootKP.getPublic());
            X509Certificate rootCACert = rootCertMaker.makeRootCACert(rootCSR);
            FileUtil.writeFile(ROOT_CERT_PATH, rootCACert.getEncoded());

            KeyPair midKP = SM2Util.generateKeyPair();
            X500Name midDN = buildMidCADN();
            SM2PublicKey midPub = new SM2PublicKey(midKP.getPublic().getAlgorithm(),
                (BCECPublicKey) midKP.getPublic());
            byte[] midCSR = CommonUtil.createCSR(midDN, midPub, midKP.getPrivate(),
                SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            SM2X509CertMakerTest.savePriKey(MID_PRI_PATH, (BCECPrivateKey) midKP.getPrivate(),
                (BCECPublicKey) midKP.getPublic());
            X509Certificate midCACert = rootCertMaker.makeSubCACert(midCSR);
            FileUtil.writeFile(MID_CERT_PATH, midCACert.getEncoded());

            SM2X509CertMaker midCertMaker = new SM2X509CertMaker(midKP, certExpire, midDN, snAllocator);
            KeyPair userKP = SM2Util.generateKeyPair();
            X500Name userDN = SM2X509CertMakerTest.buildSubjectDN();
            SM2PublicKey userPub = new SM2PublicKey(userKP.getPublic().getAlgorithm(),
                (BCECPublicKey) userKP.getPublic());
            byte[] userCSR = CommonUtil.createCSR(userDN, userPub, userKP.getPrivate(),
                SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            SM2X509CertMakerTest.savePriKey(USER_PRI_PATH, (BCECPrivateKey) userKP.getPrivate(),
                (BCECPublicKey) userKP.getPublic());
            X509Certificate userCert = midCertMaker.makeSSLEndEntityCert(userCSR);
            FileUtil.writeFile(USER_CERT_PATH, userCert.getEncoded());

            //根证书是自签名，所以用自己的公钥验证自己的证书
            BCECPublicKey bcRootPub = SM2CertUtil.getBCECPublicKey(rootCACert);
            rootCACert = SM2CertUtil.getX509Certificate(ROOT_CERT_PATH);
            if (!SM2CertUtil.verifyCertificate(bcRootPub, rootCACert)) {
                Assert.fail();
            }

            midCACert = SM2CertUtil.getX509Certificate(MID_CERT_PATH);
            if (!SM2CertUtil.verifyCertificate(bcRootPub, midCACert)) {
                Assert.fail();
            }

            BCECPublicKey bcMidPub = SM2CertUtil.getBCECPublicKey(midCACert);
            userCert = SM2CertUtil.getX509Certificate(USER_CERT_PATH);
            if (!SM2CertUtil.verifyCertificate(bcMidPub, userCert)) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static X500Name buildMidCADN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        builder.addRDN(BCStyle.CN, "ZZ Intermediate CA");
        return builder.build();
    }
}

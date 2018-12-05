package org.zz.gmhelper.cert.test;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.CommonUtil;
import org.zz.gmhelper.cert.SM2PfxMaker;
import org.zz.gmhelper.cert.SM2PublicKey;
import org.zz.gmhelper.cert.SM2X509CertMaker;
import org.zz.gmhelper.test.util.FileUtil;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

public class SM2PfxMakerTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMakePfx() {
        try {
            KeyPair subKP = SM2Util.generateBCECKeyPair();
            X500Name subDN = SM2X509CertMakerTest.buildSubjectDN();
            SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
                (BCECPublicKey) subKP.getPublic());
            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            SM2X509CertMaker certMaker = SM2X509CertMakerTest.buildCertMaker();
            X509Certificate cert = certMaker.makeCertificate(false,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment), csr);

            SM2PfxMaker pfxMaker = new SM2PfxMaker();
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
            PublicKey subPub = SM2Util.convertPublicKey(request.getSubjectPublicKeyInfo());
            PKCS12PfxPdu pfx = pfxMaker.makePfx(subKP.getPrivate(), subPub, cert, "12345678");
            byte[] pfxDER = pfx.getEncoded(ASN1Encoding.DER);
            FileUtil.writeFile("D:/test.pfx", pfxDER);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}

package org.zz.gmhelper.cert;

import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

public class SM2CertUtil {
    public static BCECPublicKey getBCECPublicKey(X509Certificate sm2Cert) {
        ECPublicKey pubKey = (ECPublicKey) sm2Cert.getPublicKey();
        ECPoint q = pubKey.getQ();
        ECParameterSpec parameterSpec = new ECParameterSpec(SM2Util.CURVE, SM2Util.G_POINT,
            SM2Util.SM2_ECC_N, SM2Util.SM2_ECC_H);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(q, parameterSpec);
        return new BCECPublicKey(pubKey.getAlgorithm(), pubKeySpec,
            BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 校验证书
     *
     * @param issuerPubKey 从颁发者CA证书中提取出来的公钥
     * @param cert         待校验的证书
     * @return
     */
    public static boolean verifyCertificate(BCECPublicKey issuerPubKey, X509Certificate cert) {
        try {
            cert.verify(issuerPubKey, BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception ex) {
            return false;
        }
        return true;
    }

    public static X509Certificate getX509Certificate(String certFilePath) throws IOException, CertificateException,
        NoSuchProviderException {
        InputStream is = null;
        try {
            is = new FileInputStream(certFilePath);
            return getX509Certificate(is);
        } finally {
            if (is != null) {
                is.close();
            }
        }
    }

    public static X509Certificate getX509Certificate(byte[] certBytes) throws CertificateException,
        NoSuchProviderException {
        ByteArrayInputStream bais = new ByteArrayInputStream(certBytes);
        return getX509Certificate(bais);
    }

    public static X509Certificate getX509Certificate(InputStream is) throws CertificateException,
        NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return (X509Certificate) cf.generateCertificate(is);
    }

    public static CertPath getCertificateChain(String certChainPath) throws IOException, CertificateException,
        NoSuchProviderException {
        InputStream is = null;
        try {
            is = new FileInputStream(certChainPath);
            return getCertificateChain(is);
        } finally {
            if (is != null) {
                is.close();
            }
        }
    }

    public static CertPath getCertificateChain(byte[] certChainBytes) throws CertificateException,
        NoSuchProviderException {
        ByteArrayInputStream bais = new ByteArrayInputStream(certChainBytes);
        return getCertificateChain(bais);
    }

    public static byte[] getCertificateChainBytes(CertPath certChain) throws CertificateEncodingException {
        return certChain.getEncoded("PKCS7");
    }

    public static CertPath getCertificateChain(InputStream is) throws CertificateException, NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return cf.generateCertPath(is, "PKCS7");
    }

    public static CertPath getCertificateChain(List<X509Certificate> certs) throws CertificateException,
        NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return cf.generateCertPath(certs);
    }

    public static X509Certificate getX509CertificateFromPfx(byte[] pfxDER, String passwd) throws Exception {
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passwd.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pfxDER);

        ContentInfo[] infos = pfx.getContentInfos();
        if (infos.length != 2) {
            throw new Exception("Only support one pair ContentInfo");
        }

        for (int i = 0; i != infos.length; i++) {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);
                PKCS12SafeBag[] bags = dataFact.getSafeBags();
                X509CertificateHolder certHoler = (X509CertificateHolder) bags[0].getBagValue();
                return SM2CertUtil.getX509Certificate(certHoler.getEncoded());
            }
        }

        throw new Exception("Not found X509Certificate in this pfx");
    }

    public static BCECPublicKey getPublicKeyFromPfx(byte[] pfxDER, String passwd) throws Exception {
        return SM2CertUtil.getBCECPublicKey(getX509CertificateFromPfx(pfxDER, passwd));
    }

    public static BCECPrivateKey getPrivateKeyFromPfx(byte[] pfxDER, String passwd) throws Exception {
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passwd.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pfxDER);

        ContentInfo[] infos = pfx.getContentInfos();
        if (infos.length != 2) {
            throw new Exception("Only support one pair ContentInfo");
        }

        for (int i = 0; i != infos.length; i++) {
            if (!infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);
                PKCS12SafeBag[] bags = dataFact.getSafeBags();
                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo) bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
                BCECPrivateKey privateKey = BCECUtil.convertPKCS8ToECPrivateKey(info.getEncoded());
                return privateKey;
            }
        }

        throw new Exception("Not found Private Key in this pfx");
    }
}

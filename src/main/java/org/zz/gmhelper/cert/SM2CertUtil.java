package org.zz.gmhelper.cert;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
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
}

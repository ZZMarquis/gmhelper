package org.zz.gmhelper.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.zz.gmhelper.BCECUtil;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SM2X509CertMaker {
    public static final String SIGN_ALGO_SM3WITHSM2 = "SM3withSM2";

    private long certExpire;
    private X500Name issuerDN;
    private CertSNAllocator snAllocator;
    private KeyPair issuerKeyPair;

    /**
     * @param issuerKeyPair 证书颁发者的密钥对。
     *                      其实一般的CA的私钥都是要严格保护的。
     *                      一般CA的私钥都会放在加密卡/加密机里，证书的签名由加密卡/加密机完成。
     *                      这里仅是为了演示BC库签发证书的用法，所以暂时不作太多要求。
     * @param certExpire    证书有效时间，单位毫秒
     * @param issuer        证书颁发者信息
     * @param snAllocator   维护/分配证书序列号的实例，证书序列号应该递增且不重复
     */
    public SM2X509CertMaker(KeyPair issuerKeyPair, long certExpire, X500Name issuer, CertSNAllocator snAllocator) {
        this.issuerKeyPair = issuerKeyPair;
        this.certExpire = certExpire;
        this.issuerDN = issuer;
        this.snAllocator = snAllocator;
    }

    /**
     * @param isCA     是否是颁发给CA的证书
     * @param keyUsage 证书用途
     * @param csr      CSR
     * @return
     * @throws Exception
     */
    public X509Certificate makeCertificate(boolean isCA, KeyUsage keyUsage, byte[] csr)
        throws Exception {
        PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
        PublicKey subPub = BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(request.getSubjectPublicKeyInfo());
        PrivateKey issPriv = issuerKeyPair.getPrivate();
        PublicKey issPub = issuerKeyPair.getPublic();

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(issuerDN, snAllocator.incrementAndGet(),
            new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + certExpire),
            request.getSubject(), subPub);
        v3CertGen.addExtension(Extension.subjectKeyIdentifier, false,
            extUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(subPub.getEncoded())));
        v3CertGen.addExtension(Extension.authorityKeyIdentifier, false,
            extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));

        // RFC 5280 §4.2.1.9 Basic Contraints:
        // Conforming CAs MUST include this extension in all CA certificates
        // that contain public keys used to validate digital signatures on
        // certificates and MUST mark the extension as critical in such
        // certificates.
        v3CertGen.addExtension(Extension.basicConstraints, isCA, new BasicConstraints(isCA));

        // RFC 5280 §4.2.1.3 Key Usage: When present, conforming CAs SHOULD mark this extension as critical.
        v3CertGen.addExtension(Extension.keyUsage, true, keyUsage);

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));
        cert.checkValidity(new Date());
        cert.verify(issPub);

        return cert;
    }

    private JcaContentSignerBuilder makeContentSignerBuilder(PublicKey issPub) throws Exception {
        if (issPub.getAlgorithm().equals("EC")) {
            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(SIGN_ALGO_SM3WITHSM2);
            contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            return contentSignerBuilder;
        }
        throw new Exception("Unsupported PublicKey Algorithm:" + issPub.getAlgorithm());
    }
}

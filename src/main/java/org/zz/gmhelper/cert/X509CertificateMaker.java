package org.zz.gmhelper.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.zz.gmhelper.Sm2Util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public class X509CertificateMaker {
    private static final long CERT_EXPIRE = 10L * 365 * 24 * 60 * 60 * 1000;
    private static final X500Name ISSUER_DN = buildIssuerDN();
    private static BigInteger serialNumber = new BigInteger("1");
    private static X509ExtensionUtils x509ExtensionUtils;

    static {
        try {
            x509ExtensionUtils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static X500Name buildIssuerDN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, "ZZ CA");
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        return builder.build();
    }

    public static X509Certificate makeCertificate(KeyPair issKP, boolean isCA, byte[] csr)
        throws GeneralSecurityException, IOException, OperatorCreationException {
        PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
        PublicKey subPub  = Sm2Util.convertPublicKey(
            request.getSubjectPublicKeyInfo().toASN1Primitive().getEncoded());
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
            ISSUER_DN,
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + CERT_EXPIRE),
            request.getSubject(),
            subPub);

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            x509ExtensionUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(subPub.getEncoded())));

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            x509ExtensionUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(isCA));

        v3CertGen.addExtension(
            Extension.keyUsage,
            false,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign |
                KeyUsage.cRLSign | KeyUsage.keyAgreement | KeyUsage.keyEncipherment)
        );

        X509Certificate _cert = new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    private static JcaContentSignerBuilder makeContentSignerBuilder(PublicKey issPub) {
        JcaContentSignerBuilder contentSignerBuilder;
        if (issPub instanceof RSAPublicKey) {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA");
        } else if (issPub.getAlgorithm().equals("EC")) {
            contentSignerBuilder = new JcaContentSignerBuilder("SM3withSM2");
        } else if (issPub.getAlgorithm().equals("DSA")) {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA1withDSA");
        } else if (issPub.getAlgorithm().equals("ECDSA")) {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA1withECDSA");
        } else if (issPub.getAlgorithm().equals("ECGOST3410")) {
            contentSignerBuilder = new JcaContentSignerBuilder("GOST3411withECGOST3410");
        } else {
            contentSignerBuilder = new JcaContentSignerBuilder("GOST3411WithGOST3410");
        }
        contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return contentSignerBuilder;
    }

    /**
     * 实际应用中还是应该交给数据库等可持久化的工具来维护序列号
     * @return
     */
    private static synchronized BigInteger allocateSerialNumber() {
        BigInteger tmp = serialNumber;
        serialNumber = serialNumber.add(BigInteger.ONE);
        return tmp;
    }
}

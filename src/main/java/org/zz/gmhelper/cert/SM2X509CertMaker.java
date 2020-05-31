package org.zz.gmhelper.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class SM2X509CertMaker {
  
    private static enum CertLevel {
        RootCA,
        SubCA,
        EndEntity
    } // class CertLevel

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
    public SM2X509CertMaker(KeyPair issuerKeyPair, long certExpire, X500Name issuer,
        CertSNAllocator snAllocator) {
        this.issuerKeyPair = issuerKeyPair;
        this.certExpire = certExpire;
        this.issuerDN = issuer;
        this.snAllocator = snAllocator;
    }

    /**
     * 生成根CA证书
     * 
     * @param csr CSR
     * @return 新的证书
     * @throws Exception 如果错误发生
     */
    public X509Certificate makeRootCACert(byte[] csr) 
            throws Exception {
        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        return makeCertificate(CertLevel.RootCA, null, csr, usage, null);
    }
    
    /**
     * 生成SubCA证书
     * 
     * @param csr CSR
     * @return 新的证书
     * @throws Exception 如果错误发生
     */
    public X509Certificate makeSubCACert(byte[] csr) 
            throws Exception {
        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        return makeCertificate(CertLevel.SubCA, 0, csr, usage, null);
    }

    /**
     * 生成SSL用户证书
     * 
     * @param csr CSR
     * @return 新的证书
     * @throws Exception 如果错误发生
     */
    public X509Certificate makeSSLEndEntityCert(byte[] csr) 
        throws Exception {
        return makeEndEntityCert(csr,
            new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth});
    }

    /**
     * 生成用户证书
     * 
     * @param csr CSR
     * @param extendedKeyUsages 扩展指数用途。
     * @return 新的证书
     * @throws Exception 如果错误发生
     */
    public X509Certificate makeEndEntityCert(byte[] csr,
          KeyPurposeId[] extendedKeyUsages) 
            throws Exception {
        KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement
                            | KeyUsage.dataEncipherment | KeyUsage.keyEncipherment);
        return makeCertificate(CertLevel.SubCA, null, csr, usage, extendedKeyUsages);
    }

    /**
     * @param isCA     是否是颁发给CA的证书
     * @param keyUsage 证书用途
     * @param csr      CSR
     * @return
     * @throws Exception
     */
    private X509Certificate makeCertificate(CertLevel certLevel, Integer pathLenConstrain,
        byte[] csr, KeyUsage keyUsage, KeyPurposeId[] extendedKeyUsages)
            throws Exception {
        if (certLevel == CertLevel.EndEntity) {
            if (keyUsage.hasUsages(KeyUsage.keyCertSign)) {
              throw new IllegalArgumentException(
                  "keyusage keyCertSign is not allowed in EndEntity Certificate");
            }
        }
        
        PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
        SubjectPublicKeyInfo subPub = request.getSubjectPublicKeyInfo();

        PrivateKey issPriv = issuerKeyPair.getPrivate();
        PublicKey issPub = issuerKeyPair.getPublic();
        
        X500Name subject = request.getSubject();
        String email = null;
        String commonName = null;
        /*
         * RFC 5280 §4.2.1.6 Subject
         *  Conforming implementations generating new certificates with
         *  electronic mail addresses MUST use the rfc822Name in the subject
         *  alternative name extension (Section 4.2.1.6) to describe such
         *  identities.  Simultaneous inclusion of the emailAddress attribute in
         *  the subject distinguished name to support legacy implementations is
         *  deprecated but permitted.
         */
        RDN[] rdns = subject.getRDNs();
        List<RDN> newRdns = new ArrayList<>(rdns.length);
        for (int i = 0; i < rdns.length; i++) {
            RDN rdn = rdns[i];
            
            AttributeTypeAndValue atv = rdn.getFirst();
            ASN1ObjectIdentifier type = atv.getType();
            if (BCStyle.EmailAddress.equals(type)) {
                email = IETFUtils.valueToString(atv.getValue());
            } else {
                if (BCStyle.CN.equals(type)) {
                    commonName = IETFUtils.valueToString(atv.getValue());
                }
                newRdns.add(rdn);
            }
        }
        
        List<GeneralName> subjectAltNames = new LinkedList<>();
        if (email != null) {
            subject = new X500Name(newRdns.toArray(new RDN[0]));
            subjectAltNames.add(
                new GeneralName(GeneralName.rfc822Name,
                    new DERIA5String(email, true)));
        }
        
        boolean selfSignedEECert = false;
        switch (certLevel) {
            case RootCA:
                if (issuerDN.equals(subject)) {
                    subject = issuerDN;
                } else {
                    throw new IllegalArgumentException("subject != issuer for certLevel " + CertLevel.RootCA);
                }
                break;
            case SubCA:
                if (issuerDN.equals(subject)) {
                    throw new IllegalArgumentException(
                        "subject MUST not equals issuer for certLevel " + certLevel);
                }
                break;
            default:
                if (issuerDN.equals(subject)) {
                    selfSignedEECert = true;
                    subject = issuerDN;
                }
        }

        BigInteger serialNumber = snAllocator.nextSerialNumber();
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + certExpire);
        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
            issuerDN, serialNumber,
            notBefore, notAfter,
            subject, subPub);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        v3CertGen.addExtension(Extension.subjectKeyIdentifier, false,
            extUtils.createSubjectKeyIdentifier(subPub));
        if (certLevel != CertLevel.RootCA && !selfSignedEECert) {
            v3CertGen.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));
        }

        // RFC 5280 §4.2.1.9 Basic Constraints:
        // Conforming CAs MUST include this extension in all CA certificates
        // that contain public keys used to validate digital signatures on
        // certificates and MUST mark the extension as critical in such
        // certificates.
        BasicConstraints basicConstraints;
        if (certLevel == CertLevel.EndEntity) {
            basicConstraints = new BasicConstraints(false);
        } else {
            basicConstraints = pathLenConstrain == null
                ? new BasicConstraints(true) : new BasicConstraints(pathLenConstrain.intValue());
        }
        v3CertGen.addExtension(Extension.basicConstraints, true, basicConstraints);

        // RFC 5280 §4.2.1.3 Key Usage: When present, conforming CAs SHOULD mark this extension as critical.
        v3CertGen.addExtension(Extension.keyUsage, true, keyUsage);

        if (extendedKeyUsages != null) {
            ExtendedKeyUsage xku = new ExtendedKeyUsage(extendedKeyUsages);
            v3CertGen.addExtension(Extension.extendedKeyUsage, false, xku);
          
            boolean forSSLServer = false;
            for (KeyPurposeId purposeId : extendedKeyUsages) {
                if (KeyPurposeId.id_kp_serverAuth.equals(purposeId)) {
                    forSSLServer = true;
                    break;
                }
            }

            if (forSSLServer) {
                if (commonName == null) {
                    throw new IllegalArgumentException("commonName must not be null");
                }
                GeneralName name = new GeneralName(GeneralName.dNSName,
                                      new DERIA5String(commonName, true));
                subjectAltNames.add(name);
            }
        }
        
        if (!subjectAltNames.isEmpty()) {
            v3CertGen.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(subjectAltNames.toArray(new GeneralName[0])));
        }

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));
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

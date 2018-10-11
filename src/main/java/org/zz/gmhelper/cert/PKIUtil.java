package org.zz.gmhelper.cert;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.zz.gmhelper.cert.exception.InvalidX500NameException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.Map;

public class PKIUtil {
    private static final String ALGO_NAME_SM3WITHSM2 = "SM3withSM2";
    private static AlgorithmIdentifier SIG_ALGO_ID_SM3WITHSM2 = null;
    private static AlgorithmIdentifier DIG_ALGO_ID_SM3WITHSM2 = null;

    static {
        DefaultSignatureAlgorithmIdentifierFinder sigFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        SIG_ALGO_ID_SM3WITHSM2 = sigFinder.find(ALGO_NAME_SM3WITHSM2);
        DefaultDigestAlgorithmIdentifierFinder digFinder = new DefaultDigestAlgorithmIdentifierFinder();
        DIG_ALGO_ID_SM3WITHSM2 = digFinder.find(SIG_ALGO_ID_SM3WITHSM2);
    }

    public static X500Name buildX500Name(Map<String, String> names) throws InvalidX500NameException {
        if (names == null || names.size() == 0) {
            throw new InvalidX500NameException("names can not be empty");
        }
        try {
            X500NameBuilder builder = new X500NameBuilder();
            Iterator itr = names.entrySet().iterator();
            BCStyle x500NameStyle = (BCStyle) BCStyle.INSTANCE;
            Map.Entry entry;
            while (itr.hasNext()) {
                entry = (Map.Entry) itr.next();
                ASN1ObjectIdentifier oid = x500NameStyle.attrNameToOID((String) entry.getKey());
                builder.addRDN(oid, (String) entry.getValue());
            }
            return builder.build();
        } catch (Exception ex) {
            throw new InvalidX500NameException(ex.getMessage(), ex);
        }
    }

    public static PKCS10CertificationRequest createCSR(X500Name subject, PublicKey pubKey, PrivateKey priKey)
        throws OperatorCreationException {
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, pubKey);
        ContentSigner signerBuilder = new JcaContentSignerBuilder(ALGO_NAME_SM3WITHSM2)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(priKey);
        return csrBuilder.build(signerBuilder);
    }

}

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
import java.util.Iterator;
import java.util.Map;

public class CommonUtil {
    /**
     * 如果不知道怎么填充names，可以查看org.bouncycastle.asn1.x500.style.BCStyle这个类，
     * names的key值必须是BCStyle.DefaultLookUp中存在的（可以不关心大小写）
     *
     * @param names
     * @return
     * @throws InvalidX500NameException
     */
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

    public static PKCS10CertificationRequest createCSR(X500Name subject, SM2PublicKey pubKey, PrivateKey priKey,
        String signAlgo) throws OperatorCreationException {
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, pubKey);
        ContentSigner signerBuilder = new JcaContentSignerBuilder(signAlgo)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(priKey);
        return csrBuilder.build(signerBuilder);
    }

    public static AlgorithmIdentifier findSignatureAlgorithmIdentifier(String algoName) {
        DefaultSignatureAlgorithmIdentifierFinder sigFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        return sigFinder.find(algoName);
    }

    public static AlgorithmIdentifier findDigestAlgorithmIdentifier(String algoName) {
        DefaultDigestAlgorithmIdentifierFinder digFinder = new DefaultDigestAlgorithmIdentifierFinder();
        return digFinder.find(findSignatureAlgorithmIdentifier(algoName));
    }
}

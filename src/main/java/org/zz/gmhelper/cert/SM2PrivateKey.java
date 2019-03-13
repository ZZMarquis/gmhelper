package org.zz.gmhelper.cert;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.spec.ECParameterSpec;

public class SM2PrivateKey extends BCECPrivateKey {
    private transient DERBitString sm2PublicKey;
    private boolean withCompression;

    public SM2PrivateKey(BCECPrivateKey privateKey, BCECPublicKey publicKey) {
        super(privateKey.getAlgorithm(), privateKey);
        this.sm2PublicKey = getSM2PublicKeyDetails(new SM2PublicKey(publicKey.getAlgorithm(), publicKey));
        this.withCompression = false;
    }

    @Override
    public void setPointFormat(String style) {
        withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    @Override
    public byte[] getEncoded() {
        ECParameterSpec ecSpec = getParams();
        ProviderConfiguration configuration = BouncyCastleProvider.CONFIGURATION;
        ASN1Encodable params = SM2PublicKey.ID_SM2_PUBKEY_PARAM;

        int orderBitLength;
        if (ecSpec == null) {
            orderBitLength = ECUtil.getOrderBitLength(configuration, null, this.getS());
        } else {
            orderBitLength = ECUtil.getOrderBitLength(configuration, ecSpec.getOrder(), this.getS());
        }

        PrivateKeyInfo info;
        org.bouncycastle.asn1.sec.ECPrivateKey keyStructure;

        if (sm2PublicKey != null) {
            keyStructure = new org.bouncycastle.asn1.sec.ECPrivateKey(orderBitLength, this.getS(), sm2PublicKey, params);
        } else {
            keyStructure = new org.bouncycastle.asn1.sec.ECPrivateKey(orderBitLength, this.getS(), params);
        }

        try {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), keyStructure);

            return info.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }

    private DERBitString getSM2PublicKeyDetails(SM2PublicKey pub) {
        try {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));

            return info.getPublicKeyData();
        } catch (IOException e) {   // should never happen
            return null;
        }
    }
}

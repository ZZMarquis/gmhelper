package org.zz.gmhelper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public class BCECUtil {
    private static final String ALGO_NAME_EC = "EC";
    private static final String PEM_STRING_PUBLIC = "PUBLIC KEY";
    private static final String PEM_STRING_ECPRIVATEKEY = "EC PRIVATE KEY";

    /**
     * 生成ECC密钥对
     *
     * @return ECC密钥对
     */
    public static AsymmetricCipherKeyPair generateKeyPair(ECDomainParameters domainParameters,
                                                          SecureRandom random) {
        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(domainParameters,
            random);
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
        keyGen.init(keyGenerationParams);
        return keyGen.generateKeyPair();
    }

    public static int getCurveLength(ECKeyParameters ecKey) {
        return getCurveLength(ecKey.getParameters());
    }

    public static int getCurveLength(ECDomainParameters domainParams) {
        return (domainParams.getCurve().getFieldSize() + 7) / 8;
    }

    public static byte[] convertEcPriKeyToPkcs8Der(ECPrivateKeyParameters priKey,
                                                   ECPublicKeyParameters pubKey) throws IOException {
        ECDomainParameters domainParams = priKey.getParameters();
        ECParameterSpec spec = new ECParameterSpec(domainParams.getCurve(), domainParams.getG(),
            domainParams.getN(), domainParams.getH());
        BCECPublicKey publicKey = null;
        if (pubKey != null) {
            publicKey = new BCECPublicKey(ALGO_NAME_EC, pubKey, spec,
                BouncyCastleProvider.CONFIGURATION);
        }
        BCECPrivateKey privateKey = new BCECPrivateKey(ALGO_NAME_EC, priKey, publicKey,
            spec, BouncyCastleProvider.CONFIGURATION);
        return privateKey.getEncoded();
    }

    public static String convertPkcs8DerEcPriKeyToPem(byte[] encodedKey) throws IOException {
        return convertDerEcDataToPem(PEM_STRING_ECPRIVATEKEY, encodedKey);
    }

    public static byte[] convertPemToPkcs8DerEcPriKey(String pemString) throws IOException {
        return convertPemToDerEcData(PEM_STRING_ECPRIVATEKEY, pemString);
    }

    /**
     * openssl d2i_ECPrivateKey函数要求的DER编码的私钥也是PKCS1标准的，
     * 这个工具函数的主要目的就是为了能生成一个openssl可以“识别”的ECC私钥
     *
     * @param priKey
     * @param pubKey
     * @return
     * @throws IOException
     */
    public static byte[] convertEcPriKeyToPkcs1Der(ECPrivateKeyParameters priKey,
                                                   ECPublicKeyParameters pubKey) throws IOException {
        byte[] pkcs8Bytes = convertEcPriKeyToPkcs8Der(priKey, pubKey);
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(pkcs8Bytes);
        ASN1Encodable encodable = pki.parsePrivateKey();
        ASN1Primitive primitive = encodable.toASN1Primitive();
        byte[] pkcs1Bytes = primitive.getEncoded();
        return pkcs1Bytes;
    }

    public static byte[] convertEcPubKeyToX509Der(ECPublicKeyParameters pubKey) {
        ECDomainParameters domainParams = pubKey.getParameters();
        ECParameterSpec spec = new ECParameterSpec(domainParams.getCurve(), domainParams.getG(),
            domainParams.getN(), domainParams.getH());
        BCECPublicKey publicKey = new BCECPublicKey(ALGO_NAME_EC, pubKey, spec,
            BouncyCastleProvider.CONFIGURATION);
        return publicKey.getEncoded();
    }

    public static String convertX509DerEcPubKeyToPem(byte[] encodedKey) throws IOException {
        return convertDerEcDataToPem(PEM_STRING_PUBLIC, encodedKey);
    }

    public static byte[] convertPemToX509DerEcPubKey(String pemString) throws IOException {
        return convertPemToDerEcData(PEM_STRING_PUBLIC, pemString);
    }

    /**
     * openssl i2d_ECPrivateKey函数生成的DER编码的ecc私钥是：PKCS1标准的、带有EC_GROUP、带有公钥的，
     * 这个工具函数的主要目的就是为了使Java程序能够“识别”openssl生成的ECC私钥
     *
     * @param encodedKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    public static ECPrivateKeyParameters convertPkcs1DerToEcPriKey(byte[] encodedKey)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        PKCS8EncodedKeySpec peks = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance(ALGO_NAME_EC, BouncyCastleProvider.PROVIDER_NAME);
        BCECPrivateKey privateKey = (BCECPrivateKey) kf.generatePrivate(peks);
        ECParameterSpec ecParameterSpec = privateKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
            ecParameterSpec.getG(), ecParameterSpec.getN(), ecParameterSpec.getH());
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(privateKey.getD(),
            ecDomainParameters);
        return priKey;
    }

    private static String convertDerEcDataToPem(String type, byte[] encodedData) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PemWriter pWrt = new PemWriter(new OutputStreamWriter(bOut));
        try {
            PemObject pemObj = new PemObject(type, encodedData);
            pWrt.writeObject(pemObj);
        } finally {
            pWrt.close();
        }
        return new String(bOut.toByteArray());
    }

    private static byte[] convertPemToDerEcData(String type, String pemString) throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(pemString.getBytes());
        PemReader pRdr = new PemReader(new InputStreamReader(bIn));
        try {
            PemObject pemObject = pRdr.readPemObject();
            return pemObject.getContent();
        } finally {
            pRdr.close();
        }
    }
}

package org.zz.gmhelper;

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

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class BCECUtil {
  private static final String ALGO_NAME_EC = "EC";

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

  /**
   * openssl i2d_ECPrivateKey函数生成的DER编码的ecc私钥是：PKCS1标准的、带有EC_GROUP、带有公钥的
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
}

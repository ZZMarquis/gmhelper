package org.zz.gmhelper;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class Sm2Util extends GmBaseUtil {
  //////////////////////////////////////////////////////////////////////////////////////
  /*
   * 以下为SM2推荐曲线参数
   */
  public final static BigInteger SM2_ECC_P = new BigInteger(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
  public final static BigInteger SM2_ECC_A = new BigInteger(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
  public final static BigInteger SM2_ECC_B = new BigInteger(
      "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
  public final static BigInteger SM2_ECC_N = new BigInteger(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
  public final static BigInteger SM2_ECC_GX = new BigInteger(
      "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
  public final static BigInteger SM2_ECC_GY = new BigInteger(
      "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
  public static final ECCurve CURVE = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B);
  public static final ECPoint G_POINT = CURVE.createPoint(SM2_ECC_GX, SM2_ECC_GY);
  public static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(CURVE, G_POINT,
      SM2_ECC_N);
  //////////////////////////////////////////////////////////////////////////////////////
  
  public static final int SM3_DIGEST_LENGTH = 32;

  /**
   * 生成ECC密钥对
   * 
   * @return ECC密钥对
   */
  public static AsymmetricCipherKeyPair generateKeyPair() {
    SecureRandom random = new SecureRandom();
    ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(DOMAIN_PARAMS,
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
  
  /**
   * ECC公钥加密
   * 
   * @param pubKey
   *          ECC公钥
   * @param srcData
   *          源数据
   * @return SM2密文，实际包含三部分：ECC公钥、真正的密文、公钥和原文的SM3-HASH值
   * @throws InvalidCipherTextException
   */
  public static byte[] encryt(ECPublicKeyParameters pubKey, byte[] srcData)
      throws InvalidCipherTextException {
    SM2Engine engine = new SM2Engine();
    ParametersWithRandom pwr = new ParametersWithRandom(pubKey, new SecureRandom());
    engine.init(true, pwr);
    return engine.processBlock(srcData, 0, srcData.length);
  }

  /**
   * ECC私钥解密
   * 
   * @param priKey
   *          ECC私钥
   * @param sm2CipherText
   *          SM2密文，实际包含三部分：ECC公钥、真正的密文、公钥和原文的SM3-HASH值
   * @return 原文
   * @throws InvalidCipherTextException
   */
  public static byte[] decrypt(ECPrivateKeyParameters priKey, byte[] sm2CipherText)
      throws InvalidCipherTextException {
    SM2Engine engine = new SM2Engine();
    engine.init(false, priKey);
    return engine.processBlock(sm2CipherText, 0, sm2CipherText.length);
  }

  /**
   * 分解SM2密文
   * 
   * @param cipherText
   *          SM2密文
   * @return
   */
  public static Sm2EncryptResult parseSm2CipherText(byte[] cipherText) {
    int curveLength = getCurveLength(DOMAIN_PARAMS);
    return parseSm2CipherText(curveLength, SM3_DIGEST_LENGTH, cipherText);
  }

  /**
   * 分解SM2密文
   * 
   * @param curveLength
   *          ECC曲线长度
   * @param digestLength
   *          HASH长度
   * @param cipherText
   *          SM2密文
   * @return
   */
  public static Sm2EncryptResult parseSm2CipherText(int curveLength, int digestLength,
      byte[] cipherText) {
    byte[] c1 = new byte[curveLength * 2 + 1];
    System.arraycopy(cipherText, 0, c1, 0, c1.length);
    byte[] c2 = new byte[cipherText.length - c1.length - digestLength];
    System.arraycopy(cipherText, c1.length, c2, 0, c2.length);
    byte[] c3 = new byte[digestLength];
    System.arraycopy(cipherText, c1.length + c2.length, c3, 0, c2.length);
    Sm2EncryptResult result = new Sm2EncryptResult();
    result.setC1(c1);
    result.setC2(c2);
    result.setC3(c3);
    result.setCipherText(cipherText);
    return result;
  }

  /**
   * ECC私钥签名
   * 不指定withId，则默认withId为字节数组:{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7, 8}
   * 
   * @param priKey
   *          ECC私钥
   * @param srcData
   *          源数据
   * @return 签名
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws CryptoException
   */
  public static byte[] sign(ECPrivateKeyParameters priKey, byte[] srcData)
      throws NoSuchAlgorithmException, NoSuchProviderException, CryptoException {
    return sign(priKey, null, srcData);
  }

  /**
   * ECC私钥签名
   * 
   * @param priKey
   *          ECC私钥
   * @param withId
   *          可以为null，若为null，则默认withId为字节数组:{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7, 8}
   * @param srcData
   *          源数据
   * @return 签名
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws CryptoException
   */
  public static byte[] sign(ECPrivateKeyParameters priKey, byte[] withId, byte[] srcData)
      throws NoSuchAlgorithmException, NoSuchProviderException, CryptoException {
    SM2Signer signer = new SM2Signer();
    CipherParameters param = null;
    ParametersWithRandom pwr = new ParametersWithRandom(priKey, new SecureRandom());
    if (withId != null) {
      param = new ParametersWithID(pwr, withId);
    } else {
      param = pwr;
    }
    signer.init(true, param);
    signer.update(srcData, 0, srcData.length);
    return signer.generateSignature();
  }

  /**
   * ECC公钥验签
   * 不指定withId，则默认withId为字节数组:{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7, 8}
   * 
   * @param pubKey
   *          ECC公钥
   * @param srcData
   *          源数据
   * @param sign
   *          签名
   * @return 验签成功返回true，失败返回false
   */
  public static boolean verify(ECPublicKeyParameters pubKey, byte[] srcData, byte[] sign) {
    return verify(pubKey, null, srcData, sign);
  }

  /**
   * ECC公钥验签
   * 
   * @param pubKey
   *          ECC公钥
   * @param withId
   *          可以为null，若为null，则默认withId为字节数组:{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7, 8}
   * @param srcData
   *          源数据
   * @param sign
   *          签名
   * @return 验签成功返回true，失败返回false
   */
  public static boolean verify(ECPublicKeyParameters pubKey, byte[] withId, byte[] srcData,
      byte[] sign) {
    SM2Signer signer = new SM2Signer();
    CipherParameters param = null;
    if (withId != null) {
      param = new ParametersWithID(pubKey, withId);
    } else {
      param = pubKey;
    }
    signer.init(false, param);
    signer.update(srcData, 0, srcData.length);
    return signer.verifySignature(sign);
  }
}

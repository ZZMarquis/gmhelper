package org.zz.gmhelper;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM2Engine.Mode;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;

public class SM2Util extends GMBaseUtil {
    //////////////////////////////////////////////////////////////////////////////////////
    /*
     * 以下为SM2推荐曲线参数
     */
    public static final SM2P256V1Curve CURVE = new SM2P256V1Curve();
    public final static BigInteger SM2_ECC_P = CURVE.getQ();
    public final static BigInteger SM2_ECC_A = CURVE.getA().toBigInteger();
    public final static BigInteger SM2_ECC_B = CURVE.getB().toBigInteger();
    public final static BigInteger SM2_ECC_N = CURVE.getOrder();
    public final static BigInteger SM2_ECC_H = CURVE.getCofactor();
    public final static BigInteger SM2_ECC_GX = new BigInteger(
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    public final static BigInteger SM2_ECC_GY = new BigInteger(
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
    public static final ECPoint G_POINT = CURVE.createPoint(SM2_ECC_GX, SM2_ECC_GY);
    public static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(CURVE, G_POINT,
            SM2_ECC_N, SM2_ECC_H);
    public static final int CURVE_LEN = BCECUtil.getCurveLength(DOMAIN_PARAMS);
    //////////////////////////////////////////////////////////////////////////////////////

    public static final EllipticCurve JDK_CURVE = new EllipticCurve(new ECFieldFp(SM2_ECC_P), SM2_ECC_A, SM2_ECC_B);
    public static final java.security.spec.ECPoint JDK_G_POINT = new java.security.spec.ECPoint(
            G_POINT.getAffineXCoord().toBigInteger(), G_POINT.getAffineYCoord().toBigInteger());
    public static final java.security.spec.ECParameterSpec JDK_EC_SPEC = new java.security.spec.ECParameterSpec(
            JDK_CURVE, JDK_G_POINT, SM2_ECC_N, SM2_ECC_H.intValue());

    //////////////////////////////////////////////////////////////////////////////////////

    public static final int SM3_DIGEST_LENGTH = 32;

    /**
     * 生成ECC密钥对
     *
     * @return ECC密钥对
     */
    public static AsymmetricCipherKeyPair generateKeyPairParameter() {
        SecureRandom random = new SecureRandom();
        return BCECUtil.generateKeyPairParameter(DOMAIN_PARAMS, random);
    }

    /**
     * 生成ECC密钥对
     *
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        SecureRandom random = new SecureRandom();
        return BCECUtil.generateKeyPair(DOMAIN_PARAMS, random);
    }

    /**
     * 只获取私钥里的d值，32字节
     *
     * @param privateKey
     * @return
     */
    public static byte[] getRawPrivateKey(BCECPrivateKey privateKey) {
        return fixToCurveLengthBytes(privateKey.getD().toByteArray());
    }

    /**
     * 只获取公钥里的XY分量，64字节
     *
     * @param publicKey
     * @return 64字节数组
     */
    public static byte[] getRawPublicKey(BCECPublicKey publicKey) {
        byte[] src65 = publicKey.getQ().getEncoded(false);
        byte[] rawXY = new byte[CURVE_LEN * 2];//SM2的话这里应该是64字节
        System.arraycopy(src65, 1, rawXY, 0, rawXY.length);
        return rawXY;
    }

    /**
     * @param pubKey  公钥
     * @param srcData 原文
     * @return 默认输出C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @throws InvalidCipherTextException
     */
    public static byte[] encrypt(BCECPublicKey pubKey, byte[] srcData) throws InvalidCipherTextException {
        ECPublicKeyParameters pubKeyParameters = BCECUtil.convertPublicKeyToParameters(pubKey);
        return encrypt(Mode.C1C3C2, pubKeyParameters, srcData);
    }

    /**
     * @param mode    指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param pubKey  公钥
     * @param srcData 原文
     * @return 根据mode不同，输出的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @throws InvalidCipherTextException
     */
    public static byte[] encrypt(Mode mode, BCECPublicKey pubKey, byte[] srcData) throws InvalidCipherTextException {
        ECPublicKeyParameters pubKeyParameters = BCECUtil.convertPublicKeyToParameters(pubKey);
        return encrypt(mode, pubKeyParameters, srcData);
    }

    /**
     * @param pubKeyParameters 公钥
     * @param srcData          原文
     * @return 默认输出C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @throws InvalidCipherTextException
     */
    public static byte[] encrypt(ECPublicKeyParameters pubKeyParameters, byte[] srcData)
            throws InvalidCipherTextException {
        return encrypt(Mode.C1C3C2, pubKeyParameters, srcData);
    }

    /**
     * @param mode             指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param pubKeyParameters 公钥
     * @param srcData          原文
     * @return 根据mode不同，输出的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @throws InvalidCipherTextException
     */
    public static byte[] encrypt(Mode mode, ECPublicKeyParameters pubKeyParameters, byte[] srcData)
            throws InvalidCipherTextException {
        SM2Engine engine = new SM2Engine(mode);
        ParametersWithRandom pwr = new ParametersWithRandom(pubKeyParameters, new SecureRandom());
        engine.init(true, pwr);
        return engine.processBlock(srcData, 0, srcData.length);
    }

    /**
     * @param priKey    私钥
     * @param sm2Cipher 默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 原文。SM2解密返回了数据则一定是原文，因为SM2自带校验，如果密文被篡改或者密钥对不上，都是会直接报异常的。
     * @throws InvalidCipherTextException
     */
    public static byte[] decrypt(BCECPrivateKey priKey, byte[] sm2Cipher) throws InvalidCipherTextException {
        ECPrivateKeyParameters priKeyParameters = BCECUtil.convertPrivateKeyToParameters(priKey);
        return decrypt(Mode.C1C3C2, priKeyParameters, sm2Cipher);
    }

    /**
     * @param mode      指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param priKey    私钥
     * @param sm2Cipher 根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 原文。SM2解密返回了数据则一定是原文，因为SM2自带校验，如果密文被篡改或者密钥对不上，都是会直接报异常的。
     * @throws InvalidCipherTextException
     */
    public static byte[] decrypt(Mode mode, BCECPrivateKey priKey, byte[] sm2Cipher) throws InvalidCipherTextException {
        ECPrivateKeyParameters priKeyParameters = BCECUtil.convertPrivateKeyToParameters(priKey);
        return decrypt(mode, priKeyParameters, sm2Cipher);
    }

    /**
     * @param priKeyParameters 私钥
     * @param sm2Cipher        默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 原文。SM2解密返回了数据则一定是原文，因为SM2自带校验，如果密文被篡改或者密钥对不上，都是会直接报异常的。
     * @throws InvalidCipherTextException
     */
    public static byte[] decrypt(ECPrivateKeyParameters priKeyParameters, byte[] sm2Cipher)
            throws InvalidCipherTextException {
        return decrypt(Mode.C1C3C2, priKeyParameters, sm2Cipher);
    }

    /**
     * @param mode             指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param priKeyParameters 私钥
     * @param sm2Cipher        根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 原文。SM2解密返回了数据则一定是原文，因为SM2自带校验，如果密文被篡改或者密钥对不上，都是会直接报异常的。
     * @throws InvalidCipherTextException
     */
    public static byte[] decrypt(Mode mode, ECPrivateKeyParameters priKeyParameters, byte[] sm2Cipher)
            throws InvalidCipherTextException {
        SM2Engine engine = new SM2Engine(mode);
        engine.init(false, priKeyParameters);
        return engine.processBlock(sm2Cipher, 0, sm2Cipher.length);
    }

    /**
     * 分解SM2密文
     *
     * @param cipherText 默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return
     * @throws Exception
     */
    public static SM2Cipher parseSM2Cipher(byte[] cipherText) throws Exception {
        int curveLength = BCECUtil.getCurveLength(DOMAIN_PARAMS);
        return parseSM2Cipher(Mode.C1C3C2, curveLength, SM3_DIGEST_LENGTH, cipherText);
    }

    /**
     * 分解SM2密文
     *
     * @param mode       指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param cipherText 根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return
     */
    public static SM2Cipher parseSM2Cipher(Mode mode, byte[] cipherText) throws Exception {
        int curveLength = BCECUtil.getCurveLength(DOMAIN_PARAMS);
        return parseSM2Cipher(mode, curveLength, SM3_DIGEST_LENGTH, cipherText);
    }

    /**
     * @param curveLength  曲线长度，SM2的话就是256位。
     * @param digestLength 摘要长度，如果是SM2的话因为默认使用SM3摘要，SM3摘要长度为32字节。
     * @param cipherText   默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return
     * @throws Exception
     */
    public static SM2Cipher parseSM2Cipher(
            int curveLength, int digestLength, byte[] cipherText) throws Exception {
        return parseSM2Cipher(Mode.C1C3C2, curveLength, digestLength, cipherText);
    }

    /**
     * 分解SM2密文
     *
     * @param mode         指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param curveLength  曲线长度，SM2的话就是256位。
     * @param digestLength 摘要长度，如果是SM2的话因为默认使用SM3摘要，SM3摘要长度为32字节。
     * @param cipherText   根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return
     */
    public static SM2Cipher parseSM2Cipher(Mode mode, int curveLength, int digestLength,
                                           byte[] cipherText) throws Exception {
        byte[] c1 = new byte[curveLength * 2 + 1];
        byte[] c2 = new byte[cipherText.length - c1.length - digestLength];
        byte[] c3 = new byte[digestLength];

        System.arraycopy(cipherText, 0, c1, 0, c1.length);
        if (mode == Mode.C1C2C3) {
            System.arraycopy(cipherText, c1.length, c2, 0, c2.length);
            System.arraycopy(cipherText, c1.length + c2.length, c3, 0, c3.length);
        } else if (mode == Mode.C1C3C2) {
            System.arraycopy(cipherText, c1.length, c3, 0, c3.length);
            System.arraycopy(cipherText, c1.length + c3.length, c2, 0, c2.length);
        } else {
            throw new Exception("Unsupported mode:" + mode);
        }

        SM2Cipher result = new SM2Cipher();
        result.setC1(c1);
        result.setC2(c2);
        result.setC3(c3);
        result.setCipherText(cipherText);
        return result;
    }

    /**
     * DER编码密文
     *
     * @param cipher 默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return DER编码后的密文
     * @throws IOException
     */
    public static byte[] encodeSM2CipherToDER(byte[] cipher) throws Exception {
        int curveLength = BCECUtil.getCurveLength(DOMAIN_PARAMS);
        return encodeSM2CipherToDER(Mode.C1C3C2, curveLength, SM3_DIGEST_LENGTH, cipher);
    }

    /**
     * DER编码密文
     *
     * @param mode   指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param cipher 根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 按指定mode DER编码后的密文
     * @throws Exception
     */
    public static byte[] encodeSM2CipherToDER(Mode mode, byte[] cipher) throws Exception {
        int curveLength = BCECUtil.getCurveLength(DOMAIN_PARAMS);
        return encodeSM2CipherToDER(mode, curveLength, SM3_DIGEST_LENGTH, cipher);
    }

    /**
     * DER编码密文
     *
     * @param curveLength  曲线长度，SM2的话就是256位。
     * @param digestLength 摘要长度，如果是SM2的话因为默认使用SM3摘要，SM3摘要长度为32字节。
     * @param cipher       默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 默认输出按C1C3C2编码的结果
     * @throws IOException
     */
    public static byte[] encodeSM2CipherToDER(int curveLength, int digestLength, byte[] cipher)
            throws Exception {
        return encodeSM2CipherToDER(Mode.C1C3C2, curveLength, digestLength, cipher);
    }

    /**
     * @param mode         指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param curveLength  曲线长度，SM2的话就是256位。
     * @param digestLength 摘要长度，如果是SM2的话因为默认使用SM3摘要，SM3摘要长度为32字节。
     * @param cipher       根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 按指定mode DER编码后的密文
     * @throws Exception
     */
    public static byte[] encodeSM2CipherToDER(Mode mode, int curveLength, int digestLength, byte[] cipher)
            throws Exception {

        byte[] c1x = new byte[curveLength];
        byte[] c1y = new byte[curveLength];
        byte[] c2 = new byte[cipher.length - c1x.length - c1y.length - 1 - digestLength];
        byte[] c3 = new byte[digestLength];

        int startPos = 1;
        System.arraycopy(cipher, startPos, c1x, 0, c1x.length);
        startPos += c1x.length;
        System.arraycopy(cipher, startPos, c1y, 0, c1y.length);
        startPos += c1y.length;
        if (mode == Mode.C1C2C3) {
            System.arraycopy(cipher, startPos, c2, 0, c2.length);
            startPos += c2.length;
            System.arraycopy(cipher, startPos, c3, 0, c3.length);
        } else if (mode == Mode.C1C3C2) {
            System.arraycopy(cipher, startPos, c3, 0, c3.length);
            startPos += c3.length;
            System.arraycopy(cipher, startPos, c2, 0, c2.length);
        } else {
            throw new Exception("Unsupported mode:" + mode);
        }

        ASN1Encodable[] arr = new ASN1Encodable[4];
        // c1x,c1y的第一个bit可能为1，这个时候要确保他们表示的大数一定是正数，所以new BigInteger符号强制设为正。
        arr[0] = new ASN1Integer(new BigInteger(1, c1x));
        arr[1] = new ASN1Integer(new BigInteger(1, c1y));
        if (mode == Mode.C1C2C3) {
            arr[2] = new DEROctetString(c2);
            arr[3] = new DEROctetString(c3);
        } else if (mode == Mode.C1C3C2) {
            arr[2] = new DEROctetString(c3);
            arr[3] = new DEROctetString(c2);
        }
        DERSequence ds = new DERSequence(arr);
        return ds.getEncoded(ASN1Encoding.DER);
    }

    /**
     * 解码DER密文
     *
     * @param derCipher 默认输入按C1C3C2顺序DER编码的密文
     * @return 输出按C1C3C2排列的字节数组，C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     */
    public static byte[] decodeDERSM2Cipher(byte[] derCipher) throws Exception {
        return decodeDERSM2Cipher(Mode.C1C3C2, derCipher);
    }

    /**
     * @param mode      指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param derCipher 根据mode输入C1C2C3或C1C3C2顺序DER编码后的密文
     * @return 根据mode不同，输出的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @throws Exception
     */
    public static byte[] decodeDERSM2Cipher(Mode mode, byte[] derCipher) throws Exception {
        ASN1Sequence as = DERSequence.getInstance(derCipher);
        byte[] c1x = ((ASN1Integer) as.getObjectAt(0)).getValue().toByteArray();
        byte[] c1y = ((ASN1Integer) as.getObjectAt(1)).getValue().toByteArray();
        // c1x，c1y可能因为大正数的补0规则在第一个有效字节前面插了一个(byte)0，变成33个字节，在这里要修正回32个字节去
        c1x = fixToCurveLengthBytes(c1x);
        c1y = fixToCurveLengthBytes(c1y);
        byte[] c3;
        byte[] c2;
        if (mode == Mode.C1C2C3) {
            c2 = ((DEROctetString) as.getObjectAt(2)).getOctets();
            c3 = ((DEROctetString) as.getObjectAt(3)).getOctets();
        } else if (mode == Mode.C1C3C2) {
            c3 = ((DEROctetString) as.getObjectAt(2)).getOctets();
            c2 = ((DEROctetString) as.getObjectAt(3)).getOctets();
        } else {
            throw new Exception("Unsupported mode:" + mode);
        }

        int pos = 0;
        byte[] cipherText = new byte[1 + c1x.length + c1y.length + c2.length + c3.length];
        final byte uncompressedFlag = 0x04;
        cipherText[0] = uncompressedFlag;
        pos += 1;
        System.arraycopy(c1x, 0, cipherText, pos, c1x.length);
        pos += c1x.length;
        System.arraycopy(c1y, 0, cipherText, pos, c1y.length);
        pos += c1y.length;
        if (mode == Mode.C1C2C3) {
            System.arraycopy(c2, 0, cipherText, pos, c2.length);
            pos += c2.length;
            System.arraycopy(c3, 0, cipherText, pos, c3.length);
        } else if (mode == Mode.C1C3C2) {
            System.arraycopy(c3, 0, cipherText, pos, c3.length);
            pos += c3.length;
            System.arraycopy(c2, 0, cipherText, pos, c2.length);
        }
        return cipherText;
    }

    /**
     * 签名
     *
     * @param priKey  私钥
     * @param srcData 原文
     * @return DER编码后的签名值
     * @throws CryptoException
     */
    public static byte[] sign(BCECPrivateKey priKey, byte[] srcData) throws CryptoException {
        ECPrivateKeyParameters priKeyParameters = BCECUtil.convertPrivateKeyToParameters(priKey);
        return sign(priKeyParameters, null, srcData);
    }

    /**
     * 签名
     * 不指定withId，则默认withId为字节数组:"1234567812345678".getBytes()
     *
     * @param priKeyParameters 私钥
     * @param srcData          原文
     * @return DER编码后的签名值
     * @throws CryptoException
     */
    public static byte[] sign(ECPrivateKeyParameters priKeyParameters, byte[] srcData) throws CryptoException {
        return sign(priKeyParameters, null, srcData);
    }

    /**
     * 私钥签名
     *
     * @param priKey  私钥
     * @param withId  可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData 原文
     * @return DER编码后的签名值
     * @throws CryptoException
     */
    public static byte[] sign(BCECPrivateKey priKey, byte[] withId, byte[] srcData) throws CryptoException {
        ECPrivateKeyParameters priKeyParameters = BCECUtil.convertPrivateKeyToParameters(priKey);
        return sign(priKeyParameters, withId, srcData);
    }

    /**
     * 签名
     *
     * @param priKeyParameters 私钥
     * @param withId           可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData          源数据
     * @return DER编码后的签名值
     * @throws CryptoException
     */
    public static byte[] sign(ECPrivateKeyParameters priKeyParameters, byte[] withId, byte[] srcData)
            throws CryptoException {
        SM2Signer signer = new SM2Signer();
        CipherParameters param = null;
        ParametersWithRandom pwr = new ParametersWithRandom(priKeyParameters, new SecureRandom());
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
     * 将DER编码的SM2签名解码成64字节的纯R+S字节流
     *
     * @param derSign
     * @return 64字节数组，前32字节为R，后32字节为S
     */
    public static byte[] decodeDERSM2Sign(byte[] derSign) {
        ASN1Sequence as = DERSequence.getInstance(derSign);
        byte[] rBytes = ((ASN1Integer) as.getObjectAt(0)).getValue().toByteArray();
        byte[] sBytes = ((ASN1Integer) as.getObjectAt(1)).getValue().toByteArray();
        //由于大数的补0规则，所以可能会出现33个字节的情况，要修正回32个字节
        rBytes = fixToCurveLengthBytes(rBytes);
        sBytes = fixToCurveLengthBytes(sBytes);
        byte[] rawSign = new byte[rBytes.length + sBytes.length];
        System.arraycopy(rBytes, 0, rawSign, 0, rBytes.length);
        System.arraycopy(sBytes, 0, rawSign, rBytes.length, sBytes.length);
        return rawSign;
    }

    /**
     * 把64字节的纯R+S字节数组编码成DER编码
     *
     * @param rawSign 64字节数组形式的SM2签名值，前32字节为R，后32字节为S
     * @return DER编码后的SM2签名值
     * @throws IOException
     */
    public static byte[] encodeSM2SignToDER(byte[] rawSign) throws IOException {
        //要保证大数是正数
        BigInteger r = new BigInteger(1, extractBytes(rawSign, 0, 32));
        BigInteger s = new BigInteger(1, extractBytes(rawSign, 32, 32));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    /**
     * 验签
     *
     * @param pubKey  公钥
     * @param srcData 原文
     * @param sign    DER编码的签名值
     * @return
     */
    public static boolean verify(BCECPublicKey pubKey, byte[] srcData, byte[] sign) {
        ECPublicKeyParameters pubKeyParameters = BCECUtil.convertPublicKeyToParameters(pubKey);
        return verify(pubKeyParameters, null, srcData, sign);
    }

    /**
     * 验签
     * 不指定withId，则默认withId为字节数组:"1234567812345678".getBytes()
     *
     * @param pubKeyParameters 公钥
     * @param srcData          原文
     * @param sign             DER编码的签名值
     * @return 验签成功返回true，失败返回false
     */
    public static boolean verify(ECPublicKeyParameters pubKeyParameters, byte[] srcData, byte[] sign) {
        return verify(pubKeyParameters, null, srcData, sign);
    }

    /**
     * 验签
     *
     * @param pubKey  公钥
     * @param withId  可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData 原文
     * @param sign    DER编码的签名值
     * @return
     */
    public static boolean verify(BCECPublicKey pubKey, byte[] withId, byte[] srcData, byte[] sign) {
        ECPublicKeyParameters pubKeyParameters = BCECUtil.convertPublicKeyToParameters(pubKey);
        return verify(pubKeyParameters, withId, srcData, sign);
    }

    /**
     * 验签
     *
     * @param pubKeyParameters 公钥
     * @param withId           可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData          原文
     * @param sign             DER编码的签名值
     * @return 验签成功返回true，失败返回false
     */
    public static boolean verify(ECPublicKeyParameters pubKeyParameters, byte[] withId, byte[] srcData, byte[] sign) {
        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        if (withId != null) {
            param = new ParametersWithID(pubKeyParameters, withId);
        } else {
            param = pubKeyParameters;
        }
        signer.init(false, param);
        signer.update(srcData, 0, srcData.length);
        return signer.verifySignature(sign);
    }

    private static byte[] extractBytes(byte[] src, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(src, offset, result, 0, result.length);
        return result;
    }

    private static byte[] fixToCurveLengthBytes(byte[] src) {
        if (src.length == CURVE_LEN) {
            return src;
        }

        byte[] result = new byte[CURVE_LEN];
        if (src.length > CURVE_LEN) {
            System.arraycopy(src, src.length - result.length, result, 0, result.length);
        } else {
            System.arraycopy(src, 0, result, result.length - src.length, src.length);
        }
        return result;
    }
}

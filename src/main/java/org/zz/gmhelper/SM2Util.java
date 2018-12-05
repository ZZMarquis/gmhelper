package org.zz.gmhelper;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;

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
    public static AsymmetricCipherKeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        return BCECUtil.generateKeyPair(DOMAIN_PARAMS, random);
    }

    public static KeyPair generateBCECKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        SecureRandom random = new SecureRandom();
        ECParameterSpec parameterSpec = new ECParameterSpec(CURVE, G_POINT, SM2_ECC_N, SM2_ECC_H);
        kpg.initialize(parameterSpec, random);
        return kpg.generateKeyPair();
    }

    public static ECPrivateKeyParameters convertPrivateKey(BCECPrivateKey ecPriKey) {
        ECParameterSpec parameterSpec = ecPriKey.getParameters();
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(),
            parameterSpec.getN(), parameterSpec.getH());
        return new ECPrivateKeyParameters(ecPriKey.getD(), domainParameters);
    }

    public static ECPublicKeyParameters convertPublicKey(BCECPublicKey ecPubKey) {
        ECParameterSpec parameterSpec = ecPubKey.getParameters();
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(),
            parameterSpec.getN(), parameterSpec.getH());
        return new ECPublicKeyParameters(ecPubKey.getQ(), domainParameters);
    }

    public static BCECPublicKey convertPublicKey(byte[] x509Bytes) throws NoSuchProviderException,
        NoSuchAlgorithmException, InvalidKeySpecException {
        return BCECUtil.convertX509ToECPublicKey(x509Bytes);
    }

    public static BCECPublicKey convertPublicKey(SubjectPublicKeyInfo subPubInfo) throws NoSuchProviderException,
        NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        return convertPublicKey(subPubInfo.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    public static byte[] encrypt(BCECPublicKey pubKey, byte[] srcData) throws InvalidCipherTextException {
        ECPublicKeyParameters pubKeyParameters = convertPublicKey(pubKey);
        return encrypt(pubKeyParameters, srcData);
    }

    /**
     * ECC公钥加密
     *
     * @param pubKeyParameters ECC公钥
     * @param srcData          源数据
     * @return SM2密文，实际包含三部分：ECC公钥、真正的密文、公钥和原文的SM3-HASH值
     * @throws InvalidCipherTextException
     */
    public static byte[] encrypt(ECPublicKeyParameters pubKeyParameters, byte[] srcData)
        throws InvalidCipherTextException {
        SM2Engine engine = new SM2Engine();
        ParametersWithRandom pwr = new ParametersWithRandom(pubKeyParameters, new SecureRandom());
        engine.init(true, pwr);
        return engine.processBlock(srcData, 0, srcData.length);
    }

    public static byte[] decrypt(BCECPrivateKey priKey, byte[] sm2Cipher) throws InvalidCipherTextException {
        ECPrivateKeyParameters priKeyParameters = convertPrivateKey(priKey);
        return decrypt(priKeyParameters, sm2Cipher);
    }

    /**
     * ECC私钥解密
     *
     * @param priKeyParameters ECC私钥
     * @param sm2Cipher        SM2密文，实际包含三部分：ECC公钥、真正的密文、公钥和原文的SM3-HASH值
     * @return 原文
     * @throws InvalidCipherTextException
     */
    public static byte[] decrypt(ECPrivateKeyParameters priKeyParameters, byte[] sm2Cipher)
        throws InvalidCipherTextException {
        SM2Engine engine = new SM2Engine();
        engine.init(false, priKeyParameters);
        return engine.processBlock(sm2Cipher, 0, sm2Cipher.length);
    }

    /**
     * 分解SM2密文
     *
     * @param cipherText SM2密文
     * @return
     */
    public static SM2Cipher parseSM2Cipher(byte[] cipherText) {
        int curveLength = BCECUtil.getCurveLength(DOMAIN_PARAMS);
        return parseSM2Cipher(curveLength, SM3_DIGEST_LENGTH, cipherText);
    }

    /**
     * 分解SM2密文
     *
     * @param curveLength  ECC曲线长度
     * @param digestLength HASH长度
     * @param cipherText   SM2密文
     * @return
     */
    public static SM2Cipher parseSM2Cipher(int curveLength, int digestLength,
        byte[] cipherText) {
        byte[] c1 = new byte[curveLength * 2 + 1];
        System.arraycopy(cipherText, 0, c1, 0, c1.length);
        byte[] c2 = new byte[cipherText.length - c1.length - digestLength];
        System.arraycopy(cipherText, c1.length, c2, 0, c2.length);
        byte[] c3 = new byte[digestLength];
        System.arraycopy(cipherText, c1.length + c2.length, c3, 0, c3.length);
        SM2Cipher result = new SM2Cipher();
        result.setC1(c1);
        result.setC2(c2);
        result.setC3(c3);
        result.setCipherText(cipherText);
        return result;
    }

    /**
     * DER编码C1C2C3密文（根据《SM2密码算法使用规范》 GM/T 0009-2012）
     *
     * @param cipher
     * @return
     * @throws IOException
     */
    public static byte[] encodeSM2CipherToDER(byte[] cipher) throws IOException {
        int curveLength = BCECUtil.getCurveLength(DOMAIN_PARAMS);
        return encodeSM2CipherToDER(curveLength, SM3_DIGEST_LENGTH, cipher);
    }

    /**
     * DER编码C1C2C3密文（根据《SM2密码算法使用规范》 GM/T 0009-2012）
     *
     * @param curveLength
     * @param digestLength
     * @param cipher
     * @return
     * @throws IOException
     */
    public static byte[] encodeSM2CipherToDER(int curveLength, int digestLength, byte[] cipher)
        throws IOException {
        int startPos = 1;

        byte[] c1x = new byte[curveLength];
        System.arraycopy(cipher, startPos, c1x, 0, c1x.length);
        startPos += c1x.length;

        byte[] c1y = new byte[curveLength];
        System.arraycopy(cipher, startPos, c1y, 0, c1y.length);
        startPos += c1y.length;

        byte[] c2 = new byte[cipher.length - c1x.length - c1y.length - 1 - digestLength];
        System.arraycopy(cipher, startPos, c2, 0, c2.length);
        startPos += c2.length;

        byte[] c3 = new byte[digestLength];
        System.arraycopy(cipher, startPos, c3, 0, c3.length);

        ASN1Encodable[] arr = new ASN1Encodable[4];
        arr[0] = new ASN1Integer(c1x);
        arr[1] = new ASN1Integer(c1y);
        arr[2] = new DEROctetString(c3);
        arr[3] = new DEROctetString(c2);
        DERSequence ds = new DERSequence(arr);
        return ds.getEncoded(ASN1Encoding.DER);
    }

    /**
     * 解DER编码密文（根据《SM2密码算法使用规范》 GM/T 0009-2012）
     *
     * @param derCipher
     * @return
     */
    public static byte[] decodeDERSM2Cipher(byte[] derCipher) {
        ASN1Sequence as = DERSequence.getInstance(derCipher);
        byte[] c1x = ((ASN1Integer) as.getObjectAt(0)).getValue().toByteArray();
        byte[] c1y = ((ASN1Integer) as.getObjectAt(1)).getValue().toByteArray();
        byte[] c3 = ((DEROctetString) as.getObjectAt(2)).getOctets();
        byte[] c2 = ((DEROctetString) as.getObjectAt(3)).getOctets();

        int pos = 0;
        byte[] cipherText = new byte[1 + c1x.length + c1y.length + c2.length + c3.length];

        final byte uncompressedFlag = 0x04;
        cipherText[0] = uncompressedFlag;
        pos += 1;

        System.arraycopy(c1x, 0, cipherText, pos, c1x.length);
        pos += c1x.length;

        System.arraycopy(c1y, 0, cipherText, pos, c1y.length);
        pos += c1y.length;

        System.arraycopy(c2, 0, cipherText, pos, c2.length);
        pos += c2.length;

        System.arraycopy(c3, 0, cipherText, pos, c3.length);

        return cipherText;
    }

    public static byte[] sign(BCECPrivateKey priKey, byte[] srcData) throws NoSuchAlgorithmException,
        NoSuchProviderException, CryptoException {
        ECPrivateKeyParameters priKeyParameters = convertPrivateKey(priKey);
        return sign(priKeyParameters, null, srcData);
    }

    /**
     * ECC私钥签名
     * 不指定withId，则默认withId为字节数组:"1234567812345678".getBytes()
     *
     * @param priKeyParameters ECC私钥
     * @param srcData          源数据
     * @return 签名
     * @throws CryptoException
     */
    public static byte[] sign(ECPrivateKeyParameters priKeyParameters, byte[] srcData) throws CryptoException {
        return sign(priKeyParameters, null, srcData);
    }

    public static byte[] sign(BCECPrivateKey priKey, byte[] withId, byte[] srcData) throws CryptoException {
        ECPrivateKeyParameters priKeyParameters = convertPrivateKey(priKey);
        return sign(priKeyParameters, withId, srcData);
    }

    /**
     * ECC私钥签名
     *
     * @param priKeyParameters ECC私钥
     * @param withId           可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData          源数据
     * @return 签名
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
     * 将DER编码的SM2签名解析成64字节的纯R+S字节流
     * @param derSign
     * @return
     */
    public static byte[] decodeDERSM2Sign(byte[] derSign) {
        ASN1Sequence as = DERSequence.getInstance(derSign);
        byte[] rBytes = ((ASN1Integer) as.getObjectAt(0)).getValue().toByteArray();
        byte[] sBytes = ((ASN1Integer) as.getObjectAt(1)).getValue().toByteArray();
        //由于大数的补0规则，所以可能会出现33个字节的情况，要修正回32个字节
        rBytes = fixTo32Bytes(rBytes);
        sBytes = fixTo32Bytes(sBytes);
        byte[] rawSign = new byte[rBytes.length + sBytes.length];
        System.arraycopy(rBytes, 0, rawSign, 0, rBytes.length);
        System.arraycopy(sBytes, 0, rawSign, rBytes.length, sBytes.length);
        return rawSign;
    }

    /**
     * 把64字节的纯R+S字节流转换成DER编码字节流
     * @param rawSign
     * @return
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

    public static boolean verify(BCECPublicKey pubKey, byte[] srcData, byte[] sign) {
        ECPublicKeyParameters pubKeyParameters = convertPublicKey(pubKey);
        return verify(pubKeyParameters, null, srcData, sign);
    }

    /**
     * ECC公钥验签
     * 不指定withId，则默认withId为字节数组:"1234567812345678".getBytes()
     *
     * @param pubKeyParameters ECC公钥
     * @param srcData          源数据
     * @param sign             签名
     * @return 验签成功返回true，失败返回false
     */
    public static boolean verify(ECPublicKeyParameters pubKeyParameters, byte[] srcData, byte[] sign) {
        return verify(pubKeyParameters, null, srcData, sign);
    }

    public static boolean verify(BCECPublicKey pubKey, byte[] withId, byte[] srcData, byte[] sign) {
        ECPublicKeyParameters pubKeyParameters = convertPublicKey(pubKey);
        return verify(pubKeyParameters, withId, srcData, sign);
    }

    /**
     * ECC公钥验签
     *
     * @param pubKeyParameters ECC公钥
     * @param withId           可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData          源数据
     * @param sign             签名
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

    private static byte[] fixTo32Bytes(byte[] src) {
        final int fixLen = 32;
        if (src.length == fixLen) {
            return src;
        }

        byte[] result = new byte[fixLen];
        if (src.length > fixLen) {
            System.arraycopy(src, src.length - result.length, result, 0, result.length);
        } else {
            System.arraycopy(src, result.length - src.length, result, 0, src.length);
        }
        return result;
    }
}

package org.zz.gmhelper;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;

/**
 * 有的国密需求是用户可以自己做预处理，签名验签只是对预处理的结果进行签名和验签
 */
public class SM2PreprocessSigner implements ECConstants {
    private static final int DIGEST_LENGTH = 32;   // bytes

    private final DSAKCalculator kCalculator = new RandomDSAKCalculator();
    private Digest digest = null;

    private ECDomainParameters ecParams;
    private ECPoint pubPoint;
    private ECKeyParameters ecKey;
    private byte[] userID;

    /**
     * 初始化
     *
     * @param forSigning true表示用于签名，false表示用于验签
     * @param param
     */
    public void init(boolean forSigning, CipherParameters param) {
        init(forSigning, new SM3Digest(), param);
    }

    /**
     * 初始化
     *
     * @param forSigning true表示用于签名，false表示用于验签
     * @param digest     SM2算法的话，一般是采用SM3摘要算法
     * @param param
     * @throws RuntimeException
     */
    public void init(boolean forSigning, Digest digest, CipherParameters param) throws RuntimeException {
        CipherParameters baseParam;

        if (digest.getDigestSize() != DIGEST_LENGTH) {
            throw new RuntimeException("Digest size must be " + DIGEST_LENGTH);
        }
        this.digest = digest;

        if (param instanceof ParametersWithID) {
            baseParam = ((ParametersWithID) param).getParameters();
            userID = ((ParametersWithID) param).getID();
        } else {
            baseParam = param;
            userID = Hex.decode("31323334353637383132333435363738"); // the default value
        }

        if (forSigning) {
            if (baseParam instanceof ParametersWithRandom) {
                ParametersWithRandom rParam = (ParametersWithRandom) baseParam;

                ecKey = (ECKeyParameters) rParam.getParameters();
                ecParams = ecKey.getParameters();
                kCalculator.init(ecParams.getN(), rParam.getRandom());
            } else {
                ecKey = (ECKeyParameters) baseParam;
                ecParams = ecKey.getParameters();
                kCalculator.init(ecParams.getN(), CryptoServicesRegistrar.getSecureRandom());
            }
            pubPoint = createBasePointMultiplier().multiply(ecParams.getG(), ((ECPrivateKeyParameters) ecKey).getD()).normalize();
        } else {
            ecKey = (ECKeyParameters) baseParam;
            ecParams = ecKey.getParameters();
            pubPoint = ((ECPublicKeyParameters) ecKey).getQ();
        }
    }

    /**
     * 预处理，辅助方法
     * ZA=H256(ENT LA ∥ IDA ∥ a ∥ b ∥ xG ∥yG ∥ xA ∥ yA)。
     * M=ZA ∥ M；
     * e = Hv(M)
     *
     * @return
     */
    public byte[] preprocess(byte[] m, int off, int len) {
        byte[] z = getZ(userID);
        digest.update(z, 0, z.length);
        digest.update(m, off, len);
        byte[] eHash = new byte[DIGEST_LENGTH];
        digest.doFinal(eHash, 0);
        return eHash;
    }

    public boolean verifySignature(byte[] eHash, byte[] signature) {
        try {
            BigInteger[] rs = derDecode(signature);
            if (rs != null) {
                return verifySignature(eHash, rs[0], rs[1]);
            }
        } catch (IOException e) {
        }

        return false;
    }

    public void reset() {
        digest.reset();
    }

    public byte[] generateSignature(byte[] eHash) throws CryptoException {
        BigInteger n = ecParams.getN();
        BigInteger e = calculateE(eHash);
        BigInteger d = ((ECPrivateKeyParameters) ecKey).getD();

        BigInteger r, s;

        ECMultiplier basePointMultiplier = createBasePointMultiplier();

        // 5.2.1 Draft RFC:  SM2 Public Key Algorithms
        do // generate s
        {
            BigInteger k;
            do // generate r
            {
                // A3
                k = kCalculator.nextK();

                // A4
                ECPoint p = basePointMultiplier.multiply(ecParams.getG(), k).normalize();

                // A5
                r = e.add(p.getAffineXCoord().toBigInteger()).mod(n);
            }
            while (r.equals(ZERO) || r.add(k).equals(n));

            // A6
            BigInteger dPlus1ModN = d.add(ONE).modInverse(n);

            s = k.subtract(r.multiply(d)).mod(n);
            s = dPlus1ModN.multiply(s).mod(n);
        }
        while (s.equals(ZERO));

        // A7
        try {
            return derEncode(r, s);
        } catch (IOException ex) {
            throw new CryptoException("unable to encode signature: " + ex.getMessage(), ex);
        }
    }

    private boolean verifySignature(byte[] eHash, BigInteger r, BigInteger s) {
        BigInteger n = ecParams.getN();

        // 5.3.1 Draft RFC:  SM2 Public Key Algorithms
        // B1
        if (r.compareTo(ONE) < 0 || r.compareTo(n) >= 0) {
            return false;
        }

        // B2
        if (s.compareTo(ONE) < 0 || s.compareTo(n) >= 0) {
            return false;
        }

        // B3 eHash

        // B4
        BigInteger e = calculateE(eHash);

        // B5
        BigInteger t = r.add(s).mod(n);
        if (t.equals(ZERO)) {
            return false;
        }

        // B6
        ECPoint q = ((ECPublicKeyParameters) ecKey).getQ();
        ECPoint x1y1 = ECAlgorithms.sumOfTwoMultiplies(ecParams.getG(), s, q, t).normalize();
        if (x1y1.isInfinity()) {
            return false;
        }

        // B7
        BigInteger expectedR = e.add(x1y1.getAffineXCoord().toBigInteger()).mod(n);

        return expectedR.equals(r);
    }

    private byte[] digestDoFinal() {
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);

        reset();

        return result;
    }

    private byte[] getZ(byte[] userID) {
        digest.reset();

        addUserID(digest, userID);

        addFieldElement(digest, ecParams.getCurve().getA());
        addFieldElement(digest, ecParams.getCurve().getB());
        addFieldElement(digest, ecParams.getG().getAffineXCoord());
        addFieldElement(digest, ecParams.getG().getAffineYCoord());
        addFieldElement(digest, pubPoint.getAffineXCoord());
        addFieldElement(digest, pubPoint.getAffineYCoord());

        byte[] result = new byte[digest.getDigestSize()];

        digest.doFinal(result, 0);

        return result;
    }

    private void addUserID(Digest digest, byte[] userID) {
        int len = userID.length * 8;
        digest.update((byte) (len >> 8 & 0xFF));
        digest.update((byte) (len & 0xFF));
        digest.update(userID, 0, userID.length);
    }

    private void addFieldElement(Digest digest, ECFieldElement v) {
        byte[] p = v.getEncoded();
        digest.update(p, 0, p.length);
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    protected BigInteger calculateE(byte[] message) {
        return new BigInteger(1, message);
    }

    protected BigInteger[] derDecode(byte[] encoding)
            throws IOException {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoding));
        if (seq.size() != 2) {
            return null;
        }

        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();

        byte[] expectedEncoding = derEncode(r, s);
        if (!Arrays.constantTimeAreEqual(expectedEncoding, encoding)) {
            return null;
        }

        return new BigInteger[]{r, s};
    }

    protected byte[] derEncode(BigInteger r, BigInteger s)
            throws IOException {

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }
}

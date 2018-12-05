package org.zz.gmhelper;

import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.SM2KeyExchangePrivateParameters;
import org.bouncycastle.crypto.params.SM2KeyExchangePublicParameters;

import java.util.Arrays;

public class SM2KeyExchangeUtil {
    /**
     * @param initiator         true表示发起方，false表示响应方
     * @param keyBits           生成的密钥长度
     * @param selfStaticPriv    己方固定私钥
     * @param selfEphemeralPriv 己方临时私钥
     * @param selfId            己方ID
     * @param otherStaticPub    对方固定公钥
     * @param otherEphemeralPub 对方临时公钥
     * @param otherId           对方ID
     * @return 返回协商出的密钥，但是这个密钥是没有经过确认的
     */
    public static byte[] calculateKey(boolean initiator, int keyBits,
        ECPrivateKeyParameters selfStaticPriv, ECPrivateKeyParameters selfEphemeralPriv, byte[] selfId,
        ECPublicKeyParameters otherStaticPub, ECPublicKeyParameters otherEphemeralPub, byte[] otherId) {
        SM2KeyExchange exch = new SM2KeyExchange();
        exch.init(new ParametersWithID(
            new SM2KeyExchangePrivateParameters(initiator, selfStaticPriv, selfEphemeralPriv),
            selfId));
        return exch.calculateKey(
            keyBits,
            new ParametersWithID(new SM2KeyExchangePublicParameters(otherStaticPub, otherEphemeralPub), otherId));
    }

    /**
     * @param initiator         true表示发起方，false表示响应方
     * @param keyBits           生成的密钥长度
     * @param confirmationTag   确认信息，如果是响应方可以为null；如果是发起方则应为响应方的s1
     * @param selfStaticPriv    己方固定私钥
     * @param selfEphemeralPriv 己方临时私钥
     * @param selfId            己方ID
     * @param otherStaticPub    对方固定公钥
     * @param otherEphemeralPub 对方临时公钥
     * @param otherId           对方ID
     * @return
     */
    public static ExchangeResult calculateKeyWithConfirmation(boolean initiator, int keyBits, byte[] confirmationTag,
        ECPrivateKeyParameters selfStaticPriv, ECPrivateKeyParameters selfEphemeralPriv, byte[] selfId,
        ECPublicKeyParameters otherStaticPub, ECPublicKeyParameters otherEphemeralPub, byte[] otherId) {
        SM2KeyExchange exch = new SM2KeyExchange();
        exch.init(new ParametersWithID(
            new SM2KeyExchangePrivateParameters(initiator, selfStaticPriv, selfEphemeralPriv),
            selfId));
        byte[][] result = exch.calculateKeyWithConfirmation(
            keyBits,
            confirmationTag,
            new ParametersWithID(new SM2KeyExchangePublicParameters(otherStaticPub, otherEphemeralPub), otherId));
        ExchangeResult confirmResult = new ExchangeResult();
        confirmResult.setKey(result[0]);
        if (initiator) {
            confirmResult.setS2(result[1]);
        } else {
            confirmResult.setS1(result[1]);
            confirmResult.setS2(result[2]);
        }
        return confirmResult;
    }

    /**
     * @param s2
     * @param confirmationTag 实际上是发起方的s2
     * @return
     */
    public static boolean responderConfirm(byte[] s2, byte[] confirmationTag) {
        return Arrays.equals(s2, confirmationTag);
    }

    public static class ExchangeResult {
        private byte[] key;

        /**
         * 发起方没有s1
         */
        private byte[] s1;

        private byte[] s2;

        public byte[] getKey() {
            return key;
        }

        public void setKey(byte[] key) {
            this.key = key;
        }

        public byte[] getS1() {
            return s1;
        }

        public void setS1(byte[] s1) {
            this.s1 = s1;
        }

        public byte[] getS2() {
            return s2;
        }

        public void setS2(byte[] s2) {
            this.s2 = s2;
        }
    }
}

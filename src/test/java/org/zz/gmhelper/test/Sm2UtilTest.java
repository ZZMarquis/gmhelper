package org.zz.gmhelper.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.Sm2Util;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;

public class Sm2UtilTest extends GmBaseTest {

    @Test
    public void testSignAndVerify() {
        try {
            AsymmetricCipherKeyPair keyPair = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

            byte[] sign = Sm2Util.sign(priKey, WITH_ID, SRC_DATA);
            System.out.println("SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));
            boolean flag = Sm2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
            if (!flag) {
                Assert.assertTrue(false);
            }

            sign = Sm2Util.sign(priKey, SRC_DATA);
            System.out.println("SM2 sign without withId result:\n" + ByteUtils.toHexString(sign));
            flag = Sm2Util.verify(pubKey, SRC_DATA, sign);
            if (!flag) {
                Assert.assertTrue(false);
            }
            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.assertTrue(false);
        }
    }

    @Test
    public void testEncryptAndDecrypt() {
        try {
            AsymmetricCipherKeyPair keyPair = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

            byte[] encryptedData = Sm2Util.encrypt(pubKey, SRC_DATA);
            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(encryptedData));
            byte[] decryptedData = Sm2Util.decrypt(priKey, encryptedData);
            System.out.println("SM2 decrypt result:\n" + ByteUtils.toHexString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.assertTrue(false);
            }
            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.assertTrue(false);
        }
    }

    @Test
    public void testKeyPairEncoding() {
        try {
            AsymmetricCipherKeyPair keyPair = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] priKeyPkcs8Der = BCECUtil.convertEcPriKeyToPkcs8Der(priKey, pubKey);
            System.out.println("private key pkcs8 der length:" + priKeyPkcs8Der.length);
            System.out.println("private key pkcs8 der:" + ByteUtils.toHexString(priKeyPkcs8Der));
            writeFile("D:/ec.pkcs8.pri.der", priKeyPkcs8Der);

            String priKeyPkcs8Pem = BCECUtil.convertPkcs8DerEcPriKeyToPem(priKeyPkcs8Der);
            writeFile("D:/ec.pkcs8.pri.pem", priKeyPkcs8Pem.getBytes("UTF-8"));
            byte[] priKeyFromPem = BCECUtil.convertPemToPkcs8DerEcPriKey(priKeyPkcs8Pem);
            if (!Arrays.equals(priKeyFromPem, priKeyPkcs8Der)) {
                throw new Exception("priKeyFromPem != priKeyPkcs8Der");
            }

            ECPrivateKeyParameters newPriKey = BCECUtil.convertPkcs1DerToEcPriKey(priKeyPkcs8Der);

            byte[] priKeyPkcs1Der = BCECUtil.convertEcPriKeyToPkcs1Der(priKey, pubKey);
            System.out.println("private key pkcs1 der length:" + priKeyPkcs1Der.length);
            System.out.println("private key pkcs1 der:" + ByteUtils.toHexString(priKeyPkcs1Der));
            writeFile("D:/ec.pkcs1.pri", priKeyPkcs1Der);

            byte[] pubKeyX509Der = BCECUtil.convertEcPubKeyToX509Der(pubKey);
            System.out.println("public key der length:" + pubKeyX509Der.length);
            System.out.println("public key der:" + ByteUtils.toHexString(pubKeyX509Der));
            writeFile("D:/ec.x509.pub.der", pubKeyX509Der);

            String pubKeyX509Pem = BCECUtil.convertX509DerEcPubKeyToPem(pubKeyX509Der);
            writeFile("D:/ec.x509.pub.pem", pubKeyX509Pem.getBytes("UTF-8"));
            byte[] pubKeyFromPem = BCECUtil.convertPemToX509DerEcPubKey(pubKeyX509Pem);
            if (!Arrays.equals(pubKeyFromPem, pubKeyX509Der)) {
                throw new Exception("pubKeyFromPem != pubKeyX509Der");
            }

            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.assertTrue(false);
        }
    }

    @Test
    public void testSm2KeyRecovery() {
        try {
            String priHex = "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D";
            String xHex = "FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913";
            String yHex = "F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956";
            String encodedPubHex = "04FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956";
            String signHex = "30450220213C6CD6EBD6A4D5C2D0AB38E29D441836D1457A8118D34864C247D727831962022100D9248480342AC8513CCDF0F89A2250DC8F6EB4F2471E144E9A812E0AF497F801";
            byte[] signBytes = ByteUtils.fromHexString(signHex);
            byte[] src = ByteUtils.fromHexString("0102030405060708010203040506070801020304050607080102030405060708");
            byte[] withId = ByteUtils.fromHexString("31323334353637383132333435363738");

            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                new BigInteger(ByteUtils.fromHexString(priHex)), Sm2Util.DOMAIN_PARAMS);
            ECPublicKeyParameters pubKey = BCECUtil.createEcPublicKey(xHex, yHex, Sm2Util.CURVE, Sm2Util.DOMAIN_PARAMS);

            if (!Sm2Util.verify(pubKey, src, signBytes)) {
                System.out.println("verify failed");
                Assert.assertTrue(false);
            }

            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.assertTrue(false);
        }
    }

    @Test
    public void testSm2KeyGen2() {
        try {
            AsymmetricCipherKeyPair keyPair = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.assertTrue(false);
        }
    }

    @Test
    public void testDerEncodeSm2CipherText() {
        try {
            AsymmetricCipherKeyPair keyPair = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] encryptedData = Sm2Util.encrypt(pubKey, SRC_DATA);

            byte[] derCipher = Sm2Util.derEncodeSm2CipherText(encryptedData);
            writeFile("derCipher.dat", derCipher);

            byte[] decryptedData = Sm2Util.decrypt(priKey, Sm2Util.parseSm2CipherTextDer(derCipher));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testGenerateBCECKeyPair() {
        try {
            KeyPair keyPair = Sm2Util.generateBCECKeyPair();
            ECPrivateKeyParameters priKey = Sm2Util.convertPrivateKey((BCECPrivateKey) keyPair.getPrivate());
            ECPublicKeyParameters pubKey = Sm2Util.convertPublicKey((BCECPublicKey) keyPair.getPublic());

            byte[] sign = Sm2Util.sign(priKey, WITH_ID, SRC_DATA);
            boolean flag = Sm2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

            sign = Sm2Util.sign(priKey, SRC_DATA);
            flag = Sm2Util.verify(pubKey, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    private void writeFile(String filePath, byte[] data) throws IOException {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(filePath, "rw");
            raf.write(data);
        } finally {
            if (raf != null) {
                raf.close();
            }
        }
    }
}

package org.zz.gmhelper.test;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.Sm2Util;

public class Sm2UtilTest extends GmBaseTest {

    @Test
    public void testSignAndVerify() {
        try {
            AsymmetricCipherKeyPair keyPair = Sm2Util.generateKeyPair();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] sign = Sm2Util.sign(priKey, WITH_ID, SRC_DATA);
            System.out.println("SM2 sign with withId result:\n" + Arrays.toString(sign));
            boolean flag = Sm2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
            if (!flag) {
                Assert.assertTrue(false);
            }

            sign = Sm2Util.sign(priKey, SRC_DATA);
            System.out.println("SM2 sign without withId result:\n" + Arrays.toString(sign));
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

            byte[] encryptedData = Sm2Util.encryt(pubKey, SRC_DATA);
            System.out.println("SM2 encrypt result:\n" + Arrays.toString(encryptedData));
            byte[] decryptedData = Sm2Util.decrypt(priKey, encryptedData);
            System.out.println("SM2 decrypt result:\n" + Arrays.toString(decryptedData));
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
            System.out.println("private key pkcs8 der:" + Arrays.toString(priKeyPkcs8Der));
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
            System.out.println("private key pkcs1 der:" + Arrays.toString(priKeyPkcs1Der));
            writeFile("D:/ec.pkcs1.pri", priKeyPkcs1Der);

            byte[] pubKeyX509Der = BCECUtil.convertEcPubKeyToX509Der(pubKey);
            System.out.println("public key der length:" + pubKeyX509Der.length);
            System.out.println("public key der:" + Arrays.toString(pubKeyX509Der));
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

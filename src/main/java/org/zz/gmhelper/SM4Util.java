package org.zz.gmhelper;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class SM4Util extends GMBaseUtil {
  public static final String ALGORITHM_NAME = "SM4";
  public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";
  public static final String ALGORITHM_NAME_CBC_PADDING = "SM4/CBC/PKCS5Padding";
  public static final int DEFAULT_KEY_SIZE = 128;

  public static byte[] generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
    return SM4Util.generateKey(SM4Util.DEFAULT_KEY_SIZE);
  }

  public static byte[] generateKey(int keySize)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyGenerator kg =
        KeyGenerator.getInstance(SM4Util.ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
    kg.init(keySize, new SecureRandom());
    return kg.generateKey().getEncoded();
  }

  public static byte[] encrypt_Ecb_Padding(byte[] key, byte[] data)
      throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
          NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher =
        SM4Util.generateEcbCipher(SM4Util.ALGORITHM_NAME_ECB_PADDING, Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(data);
  }

  public static byte[] decrypt_Ecb_Padding(byte[] key, byte[] cipherText)
      throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
          NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
    Cipher cipher =
        SM4Util.generateEcbCipher(SM4Util.ALGORITHM_NAME_ECB_PADDING, Cipher.DECRYPT_MODE, key);
    return cipher.doFinal(cipherText);
  }

  public static byte[] encrypt_Cbc_Padding(byte[] key, byte[] iv, byte[] data)
      throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
          NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
          InvalidAlgorithmParameterException {
    Cipher cipher =
        SM4Util.generateCbcCipher(SM4Util.ALGORITHM_NAME_CBC_PADDING, Cipher.ENCRYPT_MODE, key, iv);
    return cipher.doFinal(data);
  }

  public static byte[] decrypt_Cbc_Padding(byte[] key, byte[] iv, byte[] cipherText)
      throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
          NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
          InvalidAlgorithmParameterException {
    Cipher cipher =
        SM4Util.generateCbcCipher(SM4Util.ALGORITHM_NAME_CBC_PADDING, Cipher.DECRYPT_MODE, key, iv);
    return cipher.doFinal(cipherText);
  }

  private static Cipher generateEcbCipher(String algorithmName, int mode, byte[] key)
      throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
          InvalidKeyException {
    Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
    Key sm4Key = new SecretKeySpec(key, SM4Util.ALGORITHM_NAME);
    cipher.init(mode, sm4Key);
    return cipher;
  }

  private static Cipher generateCbcCipher(String algorithmName, int mode, byte[] key, byte[] iv)
      throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
          NoSuchProviderException, NoSuchPaddingException {
    Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
    Key sm4Key = new SecretKeySpec(key, SM4Util.ALGORITHM_NAME);
    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
    cipher.init(mode, sm4Key, ivParameterSpec);
    return cipher;
  }
}

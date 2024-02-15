import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SessionCipher {
    byte[] iv;
    SessionKey sessionKey;
    //1. Constructor to create a SessionCipher from a SessionKey. The IV is created automatically.
    public SessionCipher(SessionKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.sessionKey = key;
        this.iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(this.iv);
    }
    //2. Constructor to create a SessionCipher from a SessionKey and an IV, given as a byte array.
    public SessionCipher(SessionKey key, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.sessionKey = key;
        this.iv = ivbytes;
    }
    //3. Return the SessionKey
    public SessionKey getSessionKey() {
        return this.sessionKey;
    }
     //4. Return the IV as a byte array
    public byte[] getIVBytes() {
        return this.iv;
    }
     //5. Attach OutputStream to which encrypted data will be written. Return result as a CipherOutputStream instance.
    CipherOutputStream openEncryptedOutputStream(OutputStream os) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(sessionKey.getKeyBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return new CipherOutputStream(os, cipher);
    }
    //6. Attach InputStream from which decrypted data will be read. Return result as a CipherInputStream instance.
    CipherInputStream openDecryptedInputStream(InputStream is) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(sessionKey.getKeyBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return new CipherInputStream(is, cipher);

    }
}

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

class SessionKey {
    SecretKey secretKey;
    //1. Constructor to create a secret key of a given length
    public SessionKey(Integer length) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(length);
        secretKey = keyGen.generateKey();
    }

    //2. Constructor to create a secret key from key material, given as a byte array
    public SessionKey(byte[] keybytes) {
        secretKey = new SecretKeySpec(keybytes,"AES");
    }
    //3. Return the secret key
    public SecretKey getSecretKey() {
        return this.secretKey;
    }
    //4. Return the secret key encoded as a byte array
    public byte[] getKeyBytes() {
        return this.secretKey.getEncoded();
    }
}

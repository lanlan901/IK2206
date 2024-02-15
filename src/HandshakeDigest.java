import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {
    private final MessageDigest messageDigest;
    //1. When an instance is created by calling the constructor,
    // which does not take any parameters, it is initialised for SHA-256 hashing
    public HandshakeDigest() throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance("SHA-256");
    }
    //2. The input to a hash function is a sequence of bytes that can be of any length.
    // The hash value is computed in an iterative way,
    // where the update method "feeds" the hash function with more input data.
    public void update(byte[] input) {
        messageDigest.update(input);
    }
    //3. The digest method returns the final digest,
    // which is the hash value computed over the data given through the one or more calls to the update method.
    public byte[] digest() {
        return messageDigest.digest();
    }
}

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
	private Cipher cipher;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	boolean flag;

	//1. Constructor to create an instance for encryption/decryption with a public key. The public key is given as a X509 certificate.
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		X509Certificate certificate = handshakeCertificate.getCertificate();
		if(certificate.getPublicKey() == null)
			System.out.println("publickey == null");
		else
			this.publicKey = certificate.getPublicKey();
		flag = true;
	}
	//2. Constructor to create an instance for encryption/decryption with a private key.
	// The private key is given as a byte array in PKCS8/DER format.
	public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException{
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		this.privateKey = keyFactory.generatePrivate(keySpec);
		flag = false;
	}

	//3. Decrypt byte array with the key, return result as a byte array
	public byte[] decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
		this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		if(flag)
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
		else
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(ciphertext);
	}

	//4. Encrypt byte array with the key, return result as a byte array
	public byte [] encrypt(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
		this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		if(flag)
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		else
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(plaintext);
	}
}

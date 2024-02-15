import java.util.Arrays;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import org.junit.Test;


public class HandshakeDigestTest {
	
    private byte[] data = {(byte) 0x88, (byte) 0x91, (byte) 0x67, (byte) 0xc7,
						   (byte) 0x44, (byte) 0xa4, (byte) 0xc8, (byte) 0x2d,
						   (byte) 0x81, (byte) 0x41, (byte) 0xb4, (byte) 0xce,
						   (byte) 0x4f, (byte) 0x38, (byte) 0xc7, (byte) 0xd1};

	private byte[] singlehash = {(byte) 0xbc, (byte) 0xd6, (byte) 0x1d, (byte) 0x63,
								 (byte) 0xce, (byte) 0x57, (byte) 0x56, (byte) 0xb7,
								 (byte) 0x69, (byte) 0x6c, (byte) 0xee, (byte) 0xb4,
								 (byte) 0xe3, (byte) 0xb4, (byte) 0xd5, (byte) 0x07,
								 (byte) 0x64, (byte) 0x80, (byte) 0x4f, (byte) 0x04,
								 (byte) 0xb3, (byte) 0x3a, (byte) 0x5b, (byte) 0x88,
								 (byte) 0x1b, (byte) 0xd4, (byte) 0xe4, (byte) 0xa9,
								 (byte) 0x09, (byte) 0x69, (byte) 0x5b, (byte) 0xe9};

	private static void printbytes(byte[] bytes) {
		for (byte b: bytes) {
			int v = (int) b;
			System.out.format("(byte) 0x%02x, ", v & 0xff);
		}
	}

	/*
	 * Hash one data item and check that digest is correct
	 */
    @Test
    public void testSingleDataGivesDigest() throws NoSuchAlgorithmException {
		HandshakeDigest digest = new HandshakeDigest();

		digest.update(data);
		byte[] hash = digest.digest();
        assertArrayEquals(hash, singlehash);
    }

	private byte[] multihash = {(byte) 0xf4, (byte) 0xa3, (byte) 0x43, (byte) 0xd1,
								(byte) 0xa3, (byte) 0xc8, (byte) 0x7b, (byte) 0x09,
								(byte) 0x27, (byte) 0x0f, (byte) 0x05, (byte) 0xaa,
								(byte) 0xdd, (byte) 0x47, (byte) 0x6f, (byte) 0xd7,
								(byte) 0x1c, (byte) 0xd0, (byte) 0xa9, (byte) 0x87,
								(byte) 0x21, (byte) 0x19, (byte) 0x08, (byte) 0x30,
								(byte) 0xab, (byte) 0x9b, (byte) 0xbc, (byte) 0x08,
								(byte) 0x13, (byte) 0xe3, (byte) 0xd8, (byte) 0x56};
		
    @Test
    public void testMultipleDataGivesDigest() throws NoSuchAlgorithmException {
		HandshakeDigest digest = new HandshakeDigest();

		digest.update(data);
		digest.update(data);
		digest.update(data);
		digest.update(data);
		byte[] hash = digest.digest();
        assertArrayEquals(hash, multihash);
    }
}


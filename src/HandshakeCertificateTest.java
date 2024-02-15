import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;


public class HandshakeCertificateTest  {
    static String TESTCERTIFICATEFILE = "user-cert.pem";
    static String TESTCACERTIFICATEFILE = "ca-cert.pem";
    static String CERTIFICATEFILE = "user.pem";
    static String CACERTIFICATEFILE = "CA.pem";

    @Test
    void testCertFromFile() throws FileNotFoundException, CertificateException, CertificateEncodingException, IOException {

		/* Read user certificate from file and create HandshakeCertificate */
		FileInputStream instream = null;
		instream = new FileInputStream(CERTIFICATEFILE);
        HandshakeCertificate handshakeCertificate1 = new HandshakeCertificate(instream);
		/* Extract X509 certificate and encode it as a byte array */
        X509Certificate cert1 = handshakeCertificate1.getCertificate();
        byte[] certBytes1 = handshakeCertificate1.getBytes();
		/* Create another HandshakeCertificate from the byte array */
        HandshakeCertificate handshakeCertificate2 = new HandshakeCertificate(certBytes1);
        X509Certificate cert2 = handshakeCertificate2.getCertificate();
		/* Check that the two certificates are the same */
        assertEquals(cert1, cert2);
    }

    @Test
    void testByteArrayFromFile() throws FileNotFoundException, IOException, CertificateException, CertificateEncodingException {
		/* Read user certificate from file and create HandshakeCertificate */
		FileInputStream instream = null;
		instream = new FileInputStream(CERTIFICATEFILE);
        HandshakeCertificate handshakeCertificate1 = new HandshakeCertificate(instream);
		/* Extract X509 certificate and encode it as a byte array */
        X509Certificate cert1 = handshakeCertificate1.getCertificate();
        byte[] certBytes1 = handshakeCertificate1.getBytes();
		/* Create another HandshakeCertificate from the byte array */
        HandshakeCertificate handshakeCertificate2 = new HandshakeCertificate(certBytes1);
        byte[] certBytes2 = handshakeCertificate2.getBytes();
		/* Check that the two byte arrays are the same */
        assertArrayEquals(certBytes1, certBytes2);
    }

    @Test
    void testVerifyCertificate() throws FileNotFoundException, IOException, CertificateException,
                                        CertificateEncodingException, NoSuchAlgorithmException,
                                        InvalidKeyException, NoSuchProviderException, SignatureException {
		/* Read user certificate from file and create HandshakeCertificate */
        FileInputStream userinstream = null;
		userinstream = new FileInputStream(CERTIFICATEFILE);
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(userinstream);
		/* Read CA certificate from file and create HandshakeCertificate */
        FileInputStream cainstream = null;
		cainstream = new FileInputStream(CACERTIFICATEFILE);
        HandshakeCertificate CAHandshakeCertificate = new HandshakeCertificate(cainstream);
		/* Verify that user certificate is signed by CA */
        handshakeCertificate.verify(CAHandshakeCertificate);
    }

    @Test
    void testCAVerifyCertificate() throws FileNotFoundException, IOException, CertificateException,
                                        CertificateEncodingException, NoSuchAlgorithmException,
                                        InvalidKeyException, NoSuchProviderException, SignatureException {
		/* Read CA certificate from file and create HandshakeCertificate */
        FileInputStream cainstream = null;
		cainstream = new FileInputStream(TESTCACERTIFICATEFILE);
        HandshakeCertificate handshakeCACertificate = new HandshakeCertificate(cainstream);
		/* Verify that CA certificate is signed by CA */
        handshakeCACertificate.verify(handshakeCACertificate);
    }

    @Test
    void testVerifyFailCertificate() throws FileNotFoundException, IOException, CertificateException,
                                        CertificateEncodingException, NoSuchAlgorithmException,
                                        InvalidKeyException, NoSuchProviderException, SignatureException {
		/* Read user certificate from file and create HandshakeCertificate */
        FileInputStream userinstream = null;
		userinstream = new FileInputStream(TESTCERTIFICATEFILE);
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(userinstream);
		/* Check that verification fails if checking for self-signed certificate */  
		assertThrows(SignatureException.class, () -> {
				handshakeCertificate.verify(handshakeCertificate);
			}
			);
    }

    @Test
    void testCN() throws FileNotFoundException, IOException,
                         CertificateException, CertificateEncodingException {
        String TESTCN = "client.ik2206.kth.se";
		/* Read user certificate from file and create HandshakeCertificate */
        FileInputStream userinstream = null;
		userinstream = new FileInputStream(TESTCERTIFICATEFILE);
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(userinstream);
		/* Check that CN is client name */
        assertEquals(TESTCN, handshakeCertificate.getCN());
    }

    @Test
    void testEmail() throws FileNotFoundException, IOException,
                            CertificateException, CertificateEncodingException {
		/* Read user certificate from file and create HandshakeCertificate */
        FileInputStream userinstream = null;
		userinstream = new FileInputStream(TESTCERTIFICATEFILE);
        String TESTEMAIL = "client@ik2206.kth.se";
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(userinstream);
		/* Check that CN email is client email */
        assertEquals(TESTEMAIL, handshakeCertificate.getEmail());
    }
}

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.*;

import java.security.cert.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
    private final X509Certificate certificate;
     //1. Constructor to create a certificate from data read on an input stream. The data is DER-encoded, in binary or Base64 encoding (PEM format).
    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        this.certificate = (X509Certificate) certificateFactory.generateCertificate(instream);
    }
     //2. Constructor to create a certificate from its encoded representation. given as a byte array
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream inputStream = new ByteArrayInputStream(certbytes);
        this.certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }
     //3. Return the encoded representation of certificate as a byte array
    public byte[] getBytes() throws CertificateEncodingException {
        return certificate.getEncoded();
    }
     //4. Return the X509 certificate
    public X509Certificate getCertificate() {
        return certificate;
    }
     //5. Cryptographically validate a certificate. Throw relevant exception if validation fails.
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        cacert.getCertificate().checkValidity();
        PublicKey caPublicKey = cacert.getCertificate().getPublicKey();
        this.certificate.verify(caPublicKey);
    }
     //6. Return CN (Common Name) of subject
    public String getCN() {
        X500Principal principal = certificate.getSubjectX500Principal();
        String subject = principal.getName(X500Principal.RFC2253);
        Pattern cnPattern = Pattern.compile("CN=([^,]+)");
        Matcher matcher = cnPattern.matcher(subject);
        System.out.println("Subject:" + subject);
        if(matcher.find()){
            return matcher.group(1);
        }
        return null;
    }
     //7. return email address of subject
    public String getEmail() {
        X500Principal principal = certificate.getSubjectX500Principal();
        String subject = principal.getName(X500Principal.RFC2253);
        Pattern emailPattern = Pattern.compile("1.2.840.113549.1.9.1=#(\\p{XDigit}+)");
        Matcher matcher = emailPattern.matcher(subject);
        if (matcher.find()) {
            String hexEmail = matcher.group(1);
            return hexStringToString(hexEmail);
        }
        return null; // Email not found
    }
     //0. Converts a hex string to a regular string
    private static String hexStringToString(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 4; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }
}

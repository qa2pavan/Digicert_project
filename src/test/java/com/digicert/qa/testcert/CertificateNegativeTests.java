package com.digicert.qa.testcert;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.digicert.qa.certbase.validate_X509Cert;

/**
 * @author Pavan
 * The test class provodes test cases to test certificate negative scenarios
 *
 */

public class CertificateNegativeTests {
	static String current = System.getProperty("user.dir");
	private static String expiredcertificatePath = current+"\\Certificates\\expiredcert.pem";
	private static String malformedcertificatePath =current+"\\Certificates\\malformedcert.pem";
	private static X509Certificate certificate;
	@BeforeClass
    public void setup() {
        new validate_X509Cert();
    }
	
	@Test
	 public void testCertificateExpiry() throws Exception {
		certificate=validate_X509Cert.readCertificate(expiredcertificatePath);
		boolean isValid = validate_X509Cert.validateCertificate();
		Assert.assertTrue(isValid, "The certificate is expired - ");
		Date expirationDate = certificate.getNotAfter();
		System.out.println("certificate expiration date - "+expirationDate);
	}
	@Test
	 public void testCertificateExpiry_WithSpecificDate() throws Exception {
		certificate=validate_X509Cert.readCertificate(expiredcertificatePath);
		// A specific date based on milliseconds
		// NotAfter: Fri Mar 13 22:58:20 IST 2026 - 1802581290000L
		// NotBefore: Thu Mar 13 22:58:20 IST 2025 
		// Thu Mar 12 10:31:30 IST 2026 -  1773291690000L
		 
		Date specificDate = new Date(1773291690000L);
		System.out.println(specificDate);
		boolean isValid = validate_X509Cert.validateCertificateWithDate(specificDate);
		Assert.assertTrue(isValid, "The certificate is not valid by this date- "+specificDate);
	}
	
	@Test
    public void testMalformedCertificate() throws Exception {
		certificate=validate_X509Cert.readCertificate(malformedcertificatePath);
       	String sigAlgo = certificate.getSigAlgName();
       	System.out.println("malformedsignalgo --"+sigAlgo);
        Assert.assertTrue(sigAlgo.contains("SHA256"),"==The certificate at '\" + malformedcertificatePath + \"' is malformed certificate==");
        Assert.fail("--- certificate is malformed ----");
        
	}
	
	@Test
    public void testWeakCertificateKeySize() throws Exception {
		int keySize=0;
		certificate=validate_X509Cert.readCertificate(malformedcertificatePath);
       	PublicKey publicKey = certificate.getPublicKey();
        // Check if the key is an RSA key
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
             keySize = rsaPublicKey.getModulus().bitLength();
            System.out.println("keysize-"+keySize);
        }
        Assert.assertTrue(keySize==2048,"==The certificate at '\" + malformedcertificatePath + \"' is malformed certificate==");
        Assert.fail("--- certificate is malformed ----");
	}

}

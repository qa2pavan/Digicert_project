package com.digicert.qa.testcert;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.digicert.qa.certbase.validate_X509Cert;
/**
 * @author Pavan
 * the test class validate certificate structure and positive test cases
 *
 */

public class CertificateStructureValidationTest {
	static String current = System.getProperty("user.dir");
	private static String certificatePath = current+"\\Certificates\\cert.pem";
	private static X509Certificate certificate;
	@BeforeClass
    public void setup() {
        new validate_X509Cert();
    }
	
	@Test
	 public void testValidateCertificate() throws Exception {
	 certificate=validate_X509Cert.readCertificate(certificatePath);
	 boolean isValid = validate_X509Cert.validateCertificate();
	 Assert.assertTrue(isValid, "The certificate should be valid");
	}
	
	@Test
	 public void testValidateCommanName() throws Exception {
		certificate=validate_X509Cert.readCertificate(certificatePath);
		String subjectDN = certificate.getSubjectDN().getName();
		System.out.println("Subject--"+subjectDN);
		Assert.assertTrue(subjectDN.contains("CN=mydomain.com"), "Common Name is incorrect!");
	}
	
	@Test
	 public void testValidateIssuer() throws Exception {
		certificate=validate_X509Cert.readCertificate(certificatePath);
		String issuer = certificate.getIssuerDN().toString();
		System.out.println("issuer--"+issuer);
		Assert.assertTrue(issuer.contains("O=MyCompany"), "Issuer is incorrect!");
	}
	
	@Test
	 public void testValidateCertVersion() throws Exception {
		certificate=validate_X509Cert.readCertificate(certificatePath);
		int version=certificate.getVersion();
		System.out.println(version);
		Assert.assertTrue(version==3, "Cert version is incorrect");
	}
	
	@Test
	 public void testValidateCertSignatureAlgorith() throws Exception {
		certificate=validate_X509Cert.readCertificate(certificatePath);
		String sigAlgo=certificate.getSigAlgName();
		System.out.println("sigAlgo--"+sigAlgo);
		Assert.assertTrue(sigAlgo.contains("SHA256"), "Weak signature algorithm!");
	}
	
	@Test
	 public void testValidateCertExpirydate() throws Exception {
		certificate=validate_X509Cert.readCertificate(certificatePath);
		Date expirationDate = certificate.getNotAfter();
		System.out.println("certificate expiration date - "+expirationDate);
		Date currentDate = new Date();
		Assert.assertTrue(currentDate.before(expirationDate), "certificate is expired");
	}
}

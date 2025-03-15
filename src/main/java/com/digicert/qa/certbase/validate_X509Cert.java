package com.digicert.qa.certbase;

import java.io.FileInputStream;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @author Pavan
 * This is action cass for reading and validating certificate
 *
 */
public class validate_X509Cert {
	public static X509Certificate cert;
	
	public static X509Certificate readCertificate(String certificatePath) throws Exception {
		FileInputStream fis = new FileInputStream(certificatePath); {
        	CertificateFactory cf = CertificateFactory.getInstance("X.509");
          	cert = (X509Certificate) cf.generateCertificate(fis);
        }
		return cert;
	}
	
	public static boolean validateCertificate() {
        try {
        	cert.checkValidity();
            return true;
        } catch (Exception e) {
            System.out.println("Certificate validation failed: " + e.getMessage());
            return false;
        }
    }
	
	public static boolean validateCertificateWithDate(Date date) {
        try {
        	cert.checkValidity(date);
            return true;
        } catch (Exception e) {
            System.out.println("Certificate validation failed: " + e.getMessage());
            return false;
        }
    }
	
	public static int validatCertVersion() {
        try {
            int version=cert.getVersion();
            return version;
        } catch (Exception e) {
            System.out.println("Certificate validation failed: " + e.getMessage());
            return 0;
        }
    }
}

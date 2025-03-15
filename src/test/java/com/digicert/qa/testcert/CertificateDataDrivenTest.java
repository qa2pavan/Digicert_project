package com.digicert.qa.testcert;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.testng.Assert;

import com.digicert.qa.certbase.validate_X509Cert;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.ArrayList;

/**
 * @author Pavan
 * The test class implement data-driven testing to test multiple certificates
 *
 */

public class CertificateDataDrivenTest {

    
    @Test(dataProvider = "certificateProvider")
    public void testCertificateExpiration(X509Certificate certificate) {
        try {
            // Check if certificate is expired or not
            certificate.checkValidity();
            System.out.println("Certificate is valid: " + certificate.getSubjectDN());
        } catch (Exception e) {
            System.err.println("Certificate is expired: " + certificate.getSubjectDN());
            Assert.fail("Certificate is expired: " + certificate.getSubjectDN());
        }
    }

    @DataProvider(name = "certificateProvider")
    public Object[][] provideCertificates() {
        // List to store certificates
        List<X509Certificate> certificates = new ArrayList<>();
        
        try {
            // Load certificate 1
        	 String current = System.getProperty("user.dir");
            certificates.add(validate_X509Cert.readCertificate(current+"\\Certificates\\cert.pem"));
            // Load certificate 2
            certificates.add(validate_X509Cert.readCertificate(current+"\\Certificates\\cert_3072.pem"));
            // Add more certificates as needed
            certificates.add(validate_X509Cert.readCertificate(current+"\\Certificates\\cert_test.pem"));

        } catch (Exception e) {
            e.printStackTrace();
        }

        // Convert the list to a 2D Object array as required by TestNG
        Object[][] certificateData = new Object[certificates.size()][1];
        for (int i = 0; i < certificates.size(); i++) {
            certificateData[i][0] = certificates.get(i);
        }

        return certificateData;
    }
}


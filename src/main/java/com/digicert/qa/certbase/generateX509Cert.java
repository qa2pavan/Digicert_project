package com.digicert.qa.certbase;

import java.lang.Runtime;
import java.io.IOException;
import java.lang.Process;

/**
 * @author Pavan
 * This class generates new certificate based on the input provided and store in the current directory
 *
 */
public class generateX509Cert 
{
	public static Process p;
    public static void main( String[] args ){
    
    	String certinput=" -subj \"/C=US/ST=California/L=San Francisco/O=MyCompany/OU=QA/CN=mydomain.com\"";	
    	String command="openssl req -x509 -newkey rsa:2048 -keyout key5.pem -out cert5.pem -days 365 -nodes"+certinput;
    	Runtime r=Runtime.getRuntime();
    	try {
    		p=r.exec(command);
    		System.out.println("certificate is generated");
    	} catch (IOException e) {
    		e.printStackTrace();
    	}   			
    }
}

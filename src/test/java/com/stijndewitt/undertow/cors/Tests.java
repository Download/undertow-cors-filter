package com.stijndewitt.undertow.cors;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;

import com.stijndewitt.undertow.cors.AllowAll;
import com.stijndewitt.undertow.cors.AllowMatching;
import com.stijndewitt.undertow.cors.Whitelist;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for AllowAll policy.
 */
public class Tests extends TestCase {
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public Tests(String name)  {
        super(name);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(Tests.class);
    }

    /**
     * Tests the AllowAll policy
     */
    public void testAllowAll() {
    	AllowAll policy = new AllowAll(null);
        assertTrue(policy.isAllowed("https://example.com"));
        assertTrue(policy.isAllowed("http://example.com"));
        assertTrue(policy.isAllowed("https://example.org"));
        assertTrue(policy.isAllowed("http://example.org"));
        assertTrue(policy.isAllowed("https://subdomain.example.com"));
        assertTrue(policy.isAllowed("http://subdomain.example.com"));
    }
    
    /**
     * Tests the AllowMatching policy with a regex matching only (www.)example.org, only on https
     */
    public void testAllowMatching() {
    	// should allow all
    	AllowMatching policy = new AllowMatching("^.*$");
        assertTrue(policy.isAllowed("https://example.com"));
        assertTrue(policy.isAllowed("http://example.com"));
        assertTrue(policy.isAllowed("https://example.org"));
        assertTrue(policy.isAllowed("http://example.org"));
        assertTrue(policy.isAllowed("https://subdomain.example.com"));
        assertTrue(policy.isAllowed("http://subdomain.example.com"));

        // should allow only https://example.org and https://www.example.org
        policy = new AllowMatching("^https://(www\\.)?example\\.org$");
        assertTrue(policy.isAllowed("https://example.org"));
        assertTrue(policy.isAllowed("https://www.example.org"));
        
        assertFalse(policy.isAllowed("http://example.org"));
        assertFalse(policy.isAllowed("http://www.example.org"));
        assertFalse(policy.isAllowed("https://example.com"));
        assertFalse(policy.isAllowed("https://api.example.org"));
    }
    
    /**
     * Tests the Whitelist policy
     */
    public void testWhitelist() {
        try {
        	// create temp file
			File temp = File.createTempFile("undertow-cors-filter-test-whitelist", ".tmp.txt");
			PrintWriter out = new PrintWriter(temp);
			// Initial content. Blank line, comment lines, 2 regular expressions
			String content = "\n"
					+ "# blank line above should be skipped, as should this comment line\n"
					+ "// both of these are valid comment lines,\n"
					+ "// which should be skipped\n"
					+ "^http(s)?://(www\\.)?example\\.(com|org)$\n"
					+ "^http://example\\.net$";
			// write the file and close it
			out.write(content);
			out.flush();
			out.close();
			// Create a policy based on the file
	    	Whitelist policy = new Whitelist(temp.getAbsolutePath());
	    	
	    	// Whitelist should contain 2 entries
	    	assertTrue(policy.getWhitelist().size() == 2);
	    	
	    	// should match http://example.com
	        assertTrue(policy.isAllowed("http://example.com"));
	    	// should match https://example.com
	        assertTrue(policy.isAllowed("https://example.com"));
	    	// should match http://www.example.com
	        assertTrue(policy.isAllowed("http://www.example.com"));
	    	// should match https://www.example.com
	        assertTrue(policy.isAllowed("https://www.example.com"));
	    	// should match http://example.org
	        assertTrue(policy.isAllowed("http://example.org"));
	    	// should match https://example.org
	        assertTrue(policy.isAllowed("https://example.org"));
	    	// should match http://www.example.org
	        assertTrue(policy.isAllowed("http://www.example.org"));
	    	// should match https://www.example.org
	        assertTrue(policy.isAllowed("https://www.example.org"));
	    	// should match http://example.net 
	        assertTrue(policy.isAllowed("http://example.net"));
	    	
	        // should not match any other
	        assertFalse(policy.isAllowed("https://example.net"));
	        assertFalse(policy.isAllowed("http://www.example.net"));
	        assertFalse(policy.isAllowed("https://www.example.net"));
        
	        // Test if changes to whitelist file are picked up
	        content = "^http://example\\.net$";
	        // Update the file on disk. 
			out = new PrintWriter(temp);
			out.write(content);
			out.flush();
			out.close();
			
			// The change notification won't happen instantly. It's OS dependent how long
			// it takes. Apparently OSX is slowest and may take up to 5 seconds. So let's
			// give it that long to recognize the change, trying to complete the test as
			// quickly as possible but only failing after 5 seconds.
			int elapsed = 0;
			while (elapsed < 5000 && policy.getWhitelist().size() == 2) {
				// Sleep for a moment to allow the OS to process the file and notify the watcher
				Thread.sleep(25);
				elapsed += 25;
			}
			
	        // Changes should be reflected in the whitelist policy by now. If not we fail the test
	    	// Whitelist should contain 1 entry
	    	assertTrue(policy.getWhitelist().size() == 1);
	        
	    	// should match http://example.net only 
	        assertTrue(policy.isAllowed("http://example.net"));
	        // should not match any other
	        assertFalse(policy.isAllowed("https://example.net"));
	        assertFalse(policy.isAllowed("http://www.example.net"));
	        assertFalse(policy.isAllowed("https://www.example.net"));
		} catch (IOException e) {
			fail("Creating temp file for whitelist test failed: " + e.getMessage());
		} catch (InterruptedException e) {
			fail("Thread sleep interrupted: " + e.getMessage());
		}        
    }
}

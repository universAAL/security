package org.universAAL.security.profile.authenticator;

import org.universAAL.security.authenticator.profile.UserPasswordCallee;

import junit.framework.TestCase;

/**
 * Unit test for simple App.
 */
public class QueryTest 
    extends TestCase
{

    /**
     * Rigourous Test :-)
     */
    public void testGetUserQuery() {
	String s = UserPasswordCallee.getQuery("GetUserQuery", new String []{"usr1","password", "secret"});
	assertNotNull(s);
    }
    
    /**
     * Rigourous Test :-)
     */
    public void testGetDigestQuery() {
	String s = UserPasswordCallee.getQuery("GetDigestQuery", new String []{"usr1","password", "secret"});
	assertNotNull(s);
    }
}

/*******************************************************************************
 * Copyright 2013 Universidad Politécnica de Madrid
 * Copyright 2013 Fraunhofer-Gesellschaft - Institute for Computer Graphics Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

package org.universAAL.security.authenticator.client;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.xsd.Base64Binary;
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.cryptographic.digest.SecureHashAlgorithm;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.AuthenticationService;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.security.UserPasswordCredentials;

/**
 * This class is a helper for all those components that need to authenticate a user by means of
 * user password authentication.
 * 
 * @author amedrano
 *
 */
public class UserPaswordAuthenticatorClient extends DefaultServiceCaller{

	private static final String DIGEST_OUT = SecurityOntology.NAMESPACE + "digestOut";
	
	private static final String USER_OUT = SecurityOntology.NAMESPACE + "userOut";

	private static final boolean CLEAR_CALL = false;
    /**
     * Constructor
     */
    public UserPaswordAuthenticatorClient(ModuleContext mc) {
	super(mc);
    }

    /**
     * This method will try to authenticate the user. If successful the user instance will be returned
     * else it will be null.
     * @param username the username to authenticate
     * @param password the password to use for the authentication.
     * @return the {@link User} instance if successful authentication, null otherwise.
     */
    public User authenticate(String username, String password){
	try {
	    UserPasswordCredentials cred = new UserPasswordCredentials();
	    cred.setUsername(username);
	    cred.setpassword(new Base64Binary(password.getBytes("UTF-8")));
	    ServiceResponse so = null;
	    if (CLEAR_CALL){
	        so = singleCallAuthentication(cred);
	    }else {
	        so = doubleCallAuthentication(cred);
	    }
	    
	    if (so == null || !so.getCallStatus().equals(CallStatus.succeeded))
	    	   return null;
	    return (User) so.getOutput(USER_OUT, true).get(0); //XXX check all results
	} catch (UnsupportedEncodingException e) {
	   LogUtils.logError(owner,
		   getClass(),
		   "authenticate",
		   new String[]{"My eyes have yet to see this ... your system is NOT COMPATIBLE with UTF-8???"}, e);
	   return null;
	}
    }
    
    /**
     * To Be Deprecated.
     * @deprecated
     * @param cred
     * @return
     */
    private ServiceResponse singleCallAuthentication(UserPasswordCredentials cred){
	ServiceRequest sr = new ServiceRequest(new AuthenticationService(), null);
	sr.addRequiredOutput(USER_OUT, new String[]{AuthenticationService.PROP_AUTHENTICATED_USER});
	sr.addValueFilter(new String[]{AuthenticationService.PROP_GIVEN_CREDENTIALS}, cred);
	ServiceResponse so = call(sr);
	return so;
    }
    
    private ServiceResponse doubleCallAuthentication(UserPasswordCredentials cred){
	ServiceRequest sr1 = new ServiceRequest( new AuthenticationService(), null);
	sr1.addRequiredOutput(DIGEST_OUT, new String[]{AuthenticationService.PROP_GIVEN_CREDENTIALS, UserPasswordCredentials.PROP_PASSWORD_DIGEST});
	sr1.addValueFilter(new String[]{AuthenticationService.PROP_GIVEN_CREDENTIALS, UserPasswordCredentials.PROP_USERNAME}, cred.getUsername());
	// TODO ensure the call is not serialized local or remotely
	//sr1.setOriginScope(sr1.ONLY_LOCAL_SCOPE);
	ServiceResponse so = call(sr1);
	if (!so.getCallStatus().equals(CallStatus.succeeded))
	   return null;
	Digest digest = (Digest) so.getOutput(DIGEST_OUT, true).get(0); //XXX check all results

	cred.setDigestAlgorithm(digest);
	try {
	    MessageDigest dig = getMD(digest);
	    Base64Binary pwd = new Base64Binary (dig.digest(cred.getPassword().getVal()));
	    cred.setDigestAlgorithm(digest);
	    cred.setpassword(pwd);
	} catch (NoSuchAlgorithmException e) {
	    LogUtils.logWarn(owner, getClass(), "authenticate", new String[]{"unable to encrupt Password in " + digest}, e);
	}

	ServiceRequest sr2 = new ServiceRequest(new AuthenticationService(), null);
	sr2.addRequiredOutput(USER_OUT, new String[]{AuthenticationService.PROP_AUTHENTICATED_USER});
	sr2.addValueFilter(new String[]{AuthenticationService.PROP_GIVEN_CREDENTIALS}, cred);
	so = call(sr2);
	return so;
    }
    
    private MessageDigest getMD(Digest digestAlgorithm) throws NoSuchAlgorithmException{
    	//TODO call encryption service for a fully dynamic way to do this
		if (digestAlgorithm == org.universAAL.ontology.cryptographic.digest.MessageDigest.IND_MD2){
			return MessageDigest.getInstance("MD2");
		}
		if (digestAlgorithm == org.universAAL.ontology.cryptographic.digest.MessageDigest.IND_MD5){
			return MessageDigest.getInstance("MD5");
		}
		if (digestAlgorithm == SecureHashAlgorithm.IND_SHA){
			return MessageDigest.getInstance("SHA");
		}
		if (digestAlgorithm == SecureHashAlgorithm.IND_SHA256){
			return MessageDigest.getInstance("SHA-256");
		}
		if (digestAlgorithm == SecureHashAlgorithm.IND_SHA384){
			return MessageDigest.getInstance("SHA-384");
		}
		if (digestAlgorithm == SecureHashAlgorithm.IND_SHA512){
			return MessageDigest.getInstance("SHA-512");
		}
		throw new NoSuchAlgorithmException();
	}
}

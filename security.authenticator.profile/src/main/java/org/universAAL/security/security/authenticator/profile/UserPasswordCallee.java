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

package org.universAAL.security.security.authenticator.profile;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.Vector;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.middleware.rdf.PropertyPath;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceCall;
import org.universAAL.middleware.service.ServiceCallee;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.process.ProcessOutput;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.che.ContextHistoryService;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.security.UserPasswordCredentials;

/**
 * @author amedrano
 *
 */
public class UserPasswordCallee extends ServiceCallee {

    private static final String UTF_8 = "utf-8";
    private static final String OUTPUT_RESULT_STRING = SecurityOntology.NAMESPACE
	    + "outputfromCHE";
    private AuthenticatorActivator auth;
    /**
     * @param context
     * @param realizedServices
     */
    private UserPasswordCallee(ModuleContext context,
	    ServiceProfile[] realizedServices) {
	super(context, realizedServices);
    }
    
    /**
     * 
     */
    public UserPasswordCallee(AuthenticatorActivator aa) {
	this(aa.context,UserPasswordProfileService.profs);
	auth = aa;
    }

    /** {@ inheritDoc}	 */
    @Override
    public void communicationChannelBroken() {

    }

    /** {@ inheritDoc}	 */
    @Override
    public ServiceResponse handleCall(ServiceCall call) {
	if (call == null){
	    return new ServiceResponse(CallStatus.serviceSpecificFailure);
	}
	
	String cmd = call.getProcessURI();
	if (cmd.equals(UserPasswordProfileService.AUTHENTICATE_USR_PASSWORD_SERVICE)){
	    try {
		UserPasswordCredentials upc = (UserPasswordCredentials) call.getInputValue(UserPasswordProfileService.CRED_IN);
		User u = authenticate(upc.getUsername(),upc.getPassword(), upc.getDigestAlgorithm());
		if (u != null){
		ProcessOutput out = new ProcessOutput(UserPasswordProfileService.USER_OUT, u);
		ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
		sr.addOutput(out);
		return sr;
		}
	    } catch (Exception e) {
		LogUtils.logDebug(owner, getClass(), "handleCall", new String[]{"Unexpected error"}, e);		
	    }
	}
	
	if (cmd.equals(UserPasswordProfileService.GET_PWD_DIGEST_SERVICE)){
	    String username = (String) call.getInputValue(UserPasswordProfileService.USER_IN);
	    String digest = getDigestFor(username);
	    ProcessOutput out = new ProcessOutput(UserPasswordProfileService.DIGEST_OUT, digest);
	    ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
	    sr.addOutput(out);
	    return sr;
	}

	return new ServiceResponse(CallStatus.serviceSpecificFailure);
    }

    /**
     * @param username
     * @param password
     * @param digestAlgorithm
     * @return
     */
    private User authenticate(String username, String password,
	    String digestAlgorithm) {
	if (digestAlgorithm == null || digestAlgorithm.isEmpty()){
	    digestAlgorithm = getDigestFor(username);
	    try {
		MessageDigest dig = MessageDigest.getInstance(digestAlgorithm);
		password = new String (dig.digest(password.getBytes()));
	    } catch (NoSuchAlgorithmException e) {
		LogUtils.logWarn(owner, getClass(), "authenticate", new String[]{"unable to digest Password"}, e);
	    }
	}
	return (User) query("GetUserQuery", new String[]{username,password,digestAlgorithm});
    }
    
    /**
     * @param username
     * @return
     */
    private String getDigestFor(String username) {
	String dig = null;
	try {
	    dig = (String) ((Resource) query("GetDigestQuery", new String[]{username}))
	        .getProperty(UserPasswordCredentials.PROP_PASSWORD);
	} catch (Exception e) {
	    dig = null;
	}
	if (dig == null){
	    Vector<String> v = getAvailableDigests();
	    Random generator = new Random();
	    int rnd = generator.nextInt(v.size());
	    dig = v.get(rnd);
	}
	return dig;
    }
    
    private static Vector<String> getAvailableDigests(){
	Vector<String> messageDigests = new Vector<String>();
	messageDigests.add("");
	Provider[] providers = Security.getProviders();
	
	for (int i = 0; i < providers.length; i++) {
	    for (Object en : providers[i].keySet()) {
		String e = (String) en;
		if (e.startsWith("MessageDigest.")) {
		    messageDigests.add(e.substring("MessageDigest.".length()));
		}
	    }
	}
	
	return messageDigests;
    }

    private Object query(String queryFile, String[] params){
	String q = getQuery(queryFile, params);
	ServiceRequest getQuery = new ServiceRequest(
		new ContextHistoryService(null), null);

	MergedRestriction r = MergedRestriction.getFixedValueRestriction(
		ContextHistoryService.PROP_PROCESSES, q);

	getQuery.getRequestedService().addInstanceLevelRestriction(r,
		new String[] { ContextHistoryService.PROP_PROCESSES });
	getQuery.addSimpleOutputBinding(
		new ProcessOutput(OUTPUT_RESULT_STRING), new PropertyPath(null,
			true,
			new String[] { ContextHistoryService.PROP_RETURNS })
			.getThePath());
	ServiceResponse sr = new DefaultServiceCaller(owner).call(getQuery);
	List res = sr.getOutput(OUTPUT_RESULT_STRING, true);
	if (res.size() >0 && res.get(0) instanceof String){
	    return auth.getSerializer().deserialize((String) res.get(0));
	}
	return null;
    }

    public static String getQuery(String queryFile, String[] params){
	String query = "";
	try {
	    	InputStream file = UserPasswordCallee.class.getClassLoader().getResourceAsStream(queryFile);
		query = new Scanner(file,UTF_8).useDelimiter("\\Z").next();
		file.close();
	} catch (Exception e){
		/*
		 *  either:
		 *  	- empty file
		 *  	- non existent file
		 *  	- Scanner failture...
		 *  Nothing to do here
		 */
	}
	for (int i = 0; i < params.length; i++) {
	   query = query.replace("$" + Integer.toString(i+1), params[i]);
	}
	return query;
    }
}

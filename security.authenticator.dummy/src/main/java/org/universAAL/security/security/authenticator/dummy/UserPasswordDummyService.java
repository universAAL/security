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

package org.universAAL.security.security.authenticator.dummy;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.owl.SimpleOntology;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.rdf.ResourceFactory;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.AuthenticationService;
import org.universAAL.ontology.security.UserPasswordCredentials;

/**
 * @author amedrano
 *
 */
public class UserPasswordDummyService extends AuthenticationService {

    public static String NAMESPACE = "http://security.universAAL.org/Authenticator#";
    public static String MY_URI = NAMESPACE + "UserPasswordDummyAuthenticator";
    static final ServiceProfile[] profs = new ServiceProfile[1];
    
    static String AUTHENTICATE_USR_PASSWORD_SERVICE = NAMESPACE +"almostAuthenticate";
    static String CRED_IN = NAMESPACE + "credentialsIn";
    static String USER_OUT = NAMESPACE + "userOut";
    
    /**
     * @param uri
     */
    public UserPasswordDummyService(String uri) {
	super(uri);
    }

    /**
     * 
     */
    public UserPasswordDummyService() {
	super();
    }

    static void initialize(ModuleContext mc) {
	OntologyManagement.getInstance().register(mc, 
		new SimpleOntology(MY_URI, AuthenticationService.MY_URI, new ResourceFactory() {
	    
	    public Resource createInstance(String classURI, String instanceURI,
		    int factoryIndex) {
		return new UserPasswordDummyService(instanceURI);
	    }
	}));
	
	/*
	 * Authenticate profile
	 */
	UserPasswordDummyService auth = new UserPasswordDummyService(AUTHENTICATE_USR_PASSWORD_SERVICE);
	auth.addFilteringInput(CRED_IN, UserPasswordCredentials.MY_URI, 1, 1, new String[]{PROP_GIVEN_CREDENTIALS});
	auth.addOutput(USER_OUT, User.MY_URI, 1, 1, new String[]{PROP_AUTHENTICATED_USER});
	profs[0] = auth.myProfile;
    }

}

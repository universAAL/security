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

package org.universAAL.security.authenticator.profile;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.owl.SimpleOntology;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.rdf.ResourceFactory;
import org.universAAL.middleware.rdf.TypeMapper;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.security.AuthenticationService;
import org.universAAL.ontology.security.UserPasswordCredentials;

/**
 * @author amedrano
 *
 */
public class UserPasswordProfileService extends AuthenticationService {

	public static String NAMESPACE = "http://security.universAAL.org/Authenticator#";
	public static String MY_URI = NAMESPACE + "UserPasswordProfileAuthenticator";
	static final ServiceProfile[] profs = new ServiceProfile[2];

	static String AUTHENTICATE_USR_PASSWORD_SERVICE = NAMESPACE + "authenticate";
	static String CRED_IN = NAMESPACE + "credentialsIn";
	static String USER_OUT = NAMESPACE + "userOut";
	static String GET_PWD_DIGEST_SERVICE = NAMESPACE + "getDigest";
	static String USER_IN = NAMESPACE + "userIn";
	static String DIGEST_OUT = NAMESPACE + "digestOut";

	/**
	 * @param uri
	 */
	public UserPasswordProfileService(String uri) {
		super(uri);
	}

	/**
	 *
	 */
	public UserPasswordProfileService() {
		super();
	}

	static void initialize(ModuleContext mc) {
		OntologyManagement.getInstance().register(mc,
				new SimpleOntology(MY_URI, AuthenticationService.MY_URI, new ResourceFactory() {

					public Resource createInstance(String classURI, String instanceURI, int factoryIndex) {
						return new UserPasswordProfileService(instanceURI);
					}
				}));

		/*
		 * Authenticate profile
		 */
		UserPasswordProfileService auth = new UserPasswordProfileService(AUTHENTICATE_USR_PASSWORD_SERVICE);
		auth.addFilteringInput(CRED_IN, UserPasswordCredentials.MY_URI, 1, 1, new String[] { PROP_GIVEN_CREDENTIALS });
		auth.addOutput(USER_OUT, User.MY_URI, 1, 1, new String[] { PROP_AUTHENTICATED_USER });
		profs[0] = auth.myProfile;

		/*
		 * Get Digest for Username
		 */
		UserPasswordProfileService getDigest = new UserPasswordProfileService(GET_PWD_DIGEST_SERVICE);

		// getDigest.addInstanceLevelRestriction(
		// MergedRestriction.getAllValuesRestriction(PROP_GIVEN_CREDENTIALS,
		// UserPasswordCredentials.MY_URI),
		// new String[]{PROP_GIVEN_CREDENTIALS});

		getDigest.addFilteringInput(USER_IN, TypeMapper.getDatatypeURI(String.class), 1, 1,
				new String[] { PROP_GIVEN_CREDENTIALS, UserPasswordCredentials.PROP_USERNAME });
		getDigest.addOutput(DIGEST_OUT, Digest.MY_URI, 1, 1,
				new String[] { PROP_GIVEN_CREDENTIALS, UserPasswordCredentials.PROP_PASSWORD_DIGEST });
		profs[1] = getDigest.myProfile;
	}

	public String getClassURI() {
		return MY_URI;
	}
}

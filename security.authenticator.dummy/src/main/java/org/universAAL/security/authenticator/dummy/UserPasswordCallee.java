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

package org.universAAL.security.authenticator.dummy;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.ServiceCall;
import org.universAAL.middleware.service.ServiceCallee;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.process.ProcessOutput;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.middleware.util.Constants;
import org.universAAL.middleware.xsd.Base64Binary;
import org.universAAL.middleware.xsd.util.Base64;
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.cryptographic.digest.SecureHashAlgorithm;
import org.universAAL.ontology.profile.AssistedPerson;
import org.universAAL.ontology.profile.Caregiver;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.UserPasswordCredentials;

/**
 * @author amedrano
 *
 */
public class UserPasswordCallee extends ServiceCallee {

	private static final String CAREGIVER_TRIGGER = "CG";

	/**
	 * @param context
	 * @param realizedServices
	 */
	private UserPasswordCallee(ModuleContext context, ServiceProfile[] realizedServices) {
		super(context, realizedServices);
	}

	/**
	 *
	 */
	public UserPasswordCallee(ModuleContext mc) {
		this(mc, UserPasswordDummyService.profs);
	}

	/** {@ inheritDoc} */
	@Override
	public void communicationChannelBroken() {

	}

	/** {@ inheritDoc} */
	@Override
	public ServiceResponse handleCall(ServiceCall call) {
		if (call == null) {
			return new ServiceResponse(CallStatus.serviceSpecificFailure);
		}

		String cmd = call.getProcessURI();
		if (cmd.startsWith(UserPasswordDummyService.AUTHENTICATE_USR_PASSWORD_SERVICE)) {
			UserPasswordCredentials upc = (UserPasswordCredentials) call
					.getInputValue(UserPasswordDummyService.CRED_IN);
			User u = authenticate(upc.getUsername(), upc.getPassword(), upc.getDigestAlgorithm());
			if (u != null) {
				ProcessOutput out = new ProcessOutput(UserPasswordDummyService.USER_OUT, u);
				ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
				sr.addOutput(out);
				return sr;
			}
		}

		if (cmd.startsWith(UserPasswordDummyService.GET_PWD_DIGEST_SERVICE)) {
			ProcessOutput out = new ProcessOutput(UserPasswordDummyService.DIGEST_OUT, SecureHashAlgorithm.IND_SHA512);
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
	private User authenticate(String username, Base64Binary password, Digest digestAlgorithm) {
		if (username != null && !username.isEmpty()) {
			if (username.contains(CAREGIVER_TRIGGER)) {
				return new Caregiver(Constants.MIDDLEWARE_LOCAL_ID_PREFIX
						+ username.toLowerCase().replace(" ", "_").replace("#", "").replace("/", "_"));
			} else {
				return new AssistedPerson(Constants.MIDDLEWARE_LOCAL_ID_PREFIX
						+ username.toLowerCase().replace(" ", "_").replace("#", "").replace("/", "_"));
			}
		}
		return null;
	}

}

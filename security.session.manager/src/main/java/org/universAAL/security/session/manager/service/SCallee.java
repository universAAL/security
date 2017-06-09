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

package org.universAAL.security.session.manager.service;

import java.util.ArrayList;
import java.util.Set;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.ServiceCall;
import org.universAAL.middleware.service.ServiceCallee;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.process.ProcessOutput;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.location.Location;
import org.universAAL.ontology.phThing.Device;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.Session;
import org.universAAL.security.session.manager.SessionManager;

/**
 * 
 * @author amedrano
 *
 */
public class SCallee extends ServiceCallee {

	private SessionManager sm;

	// prepare a standard error message for later use
	private static final ServiceResponse invalidInput = new ServiceResponse(CallStatus.serviceSpecificFailure);
	static {
		invalidInput.addOutput(new ProcessOutput(ServiceResponse.PROP_SERVICE_SPECIFIC_ERROR, "Invalid input!"));
	}

	/**
	 * @param context
	 * @param realizedServices
	 */
	public SCallee(ModuleContext context, ServiceProfile[] realizedServices, SessionManager sessionMngr) {
		super(context, realizedServices);
		this.sm = sessionMngr;
	}

	/** {@ inheritDoc} */
	@Override
	public void communicationChannelBroken() {

	}

	/** {@ inheritDoc} */
	@Override
	public ServiceResponse handleCall(ServiceCall call) {
		if (call == null)
			return invalidInput;

		String cmd = call.getProcessURI();
		if (cmd == null)
			return invalidInput;

		ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);

		if (cmd.startsWith(SessionManagerService.SESSIONS_IN_DEVICE_SERVICE)) {
			Resource dvc = (Resource) call.getInputValue(SessionManagerService.DEV_IN);
			if (dvc == null || !(dvc instanceof Device))
				return invalidInput;
			Set<User> usrs = sm.validUsersForDevice((Device) dvc);
			sr.addOutput(new ProcessOutput(SessionManagerService.USER_PARAM, new ArrayList<User>(usrs)));
			return sr;
		}

		if (cmd.startsWith(SessionManagerService.SESSIONS_IN_LOCATIONS_SERVICE)) {
			Resource loc = (Resource) call.getInputValue(SessionManagerService.LOC_IN);
			if (loc == null || !(loc instanceof Location))
				return invalidInput;
			Set<User> usrs = sm.validUsersForLocation((Location) loc);
			sr.addOutput(new ProcessOutput(SessionManagerService.USER_PARAM, new ArrayList<User>(usrs)));
			return sr;
		}

		if (cmd.startsWith(SessionManagerService.GET_SESSION_FOR_USER_SERVICE)) {
			Resource usr = (Resource) call.getInputValue(SessionManagerService.USER_PARAM);
			if (usr == null || !(usr instanceof User))
				return invalidInput;
			Session s = sm.getCopyOfUserSession((User) usr);

			sr.addOutput(new ProcessOutput(SessionManagerService.SESSION_OUT, s));
			return sr;
		}

		return invalidInput;
	}

}

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

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.owl.SimpleOntology;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.rdf.ResourceFactory;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.location.Location;
import org.universAAL.ontology.phThing.Device;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.AuthenticationService;
import org.universAAL.ontology.security.DeviceBoundSession;
import org.universAAL.ontology.security.LocationBoundSession;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.security.Session;
import org.universAAL.ontology.security.SessionManagementService;

/**
 * @author amedrano
 *
 */
public class SessionManagerService extends SessionManagementService {

	public static final String NAMESPACE = "http://security.universAAL.org/SessionManager#";
	public static final String MY_URI = NAMESPACE + "SessionManagaerService";

	public static final ServiceProfile[] profs = new ServiceProfile[3];

	static final String SESSIONS_IN_DEVICE_SERVICE = NAMESPACE + "listDeviceSessions";
	static final String SESSIONS_IN_LOCATIONS_SERVICE = NAMESPACE + "listLocationSessions";
	static final String GET_SESSION_FOR_USER_SERVICE = NAMESPACE + "getSession";

	static final String DEV_IN = NAMESPACE + "deviceIn";
	static final String LOC_IN = NAMESPACE + "locationIn";
	static final String USER_PARAM = NAMESPACE + "userInOut";
	static final String SESSION_OUT = NAMESPACE + "validSession";

	/**
	 * @param uri
	 */
	public SessionManagerService(String uri) {
		super(uri);
	}

	/**
	 *
	 */
	public SessionManagerService() {
		super();
	}

	public static ServiceProfile[] initialize(ModuleContext mc) {
		OntologyManagement.getInstance().register(mc,
				new SimpleOntology(MY_URI, AuthenticationService.MY_URI, new ResourceFactory() {

					public Resource createInstance(String classURI, String instanceURI, int factoryIndex) {
						return new SessionManagerService(instanceURI);
					}
				}));

		/*
		 * List Valid Sessions for Device
		 */
		SessionManagerService listInD = new SessionManagerService(SESSIONS_IN_DEVICE_SERVICE);
		listInD.addFilteringInput(DEV_IN, Device.MY_URI, 1, 1,
				new String[] { PROP_USER, SecurityOntology.PROP_SESSION, DeviceBoundSession.PROP_BOUNDED_DEVICE });
		listInD.addOutput(USER_PARAM, User.MY_URI, 0, -1, new String[] { PROP_USER });
		profs[0] = listInD.myProfile;

		/*
		 * List Valid Sessions for Location
		 */
		SessionManagerService listInL = new SessionManagerService(SESSIONS_IN_LOCATIONS_SERVICE);
		listInL.addFilteringInput(LOC_IN, Location.MY_URI, 1, 1,
				new String[] { PROP_USER, SecurityOntology.PROP_SESSION, LocationBoundSession.PROP_BOUNDED_LOCATION });
		listInL.addOutput(USER_PARAM, User.MY_URI, 0, -1, new String[] { PROP_USER });
		profs[1] = listInL.myProfile;

		/*
		 * is valid for Device and User
		 */
		SessionManagerService isValidUD = new SessionManagerService(GET_SESSION_FOR_USER_SERVICE);
		isValidUD.addFilteringInput(USER_PARAM, User.MY_URI, 1, 1, new String[] { PROP_USER });
		isValidUD.addOutput(SESSION_OUT, Session.MY_URI, 0, 1,
				new String[] { PROP_USER, SecurityOntology.PROP_SESSION });
		profs[2] = isValidUD.myProfile;

		return profs;
	}
}

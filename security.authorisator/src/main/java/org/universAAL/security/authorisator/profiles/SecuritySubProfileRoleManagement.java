/*******************************************************************************
 * Copyright 2016 Universidad Politécnica de Madrid UPM
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
package org.universAAL.security.authorisator.profiles;

import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.profile.UserProfile;
import org.universAAL.ontology.profile.service.ProfilingService;
import org.universAAL.ontology.security.AuthorizationService;
import org.universAAL.ontology.security.SecuritySubprofile;
import org.universAAL.security.authorisator.ProjectActivator;

/**
 * @author amedrano
 *
 */
public class SecuritySubProfileRoleManagement extends AuthorizationService {

	public static String MY_URI = ProjectActivator.NAMESPACE + "SubProfileManagement";

	public static String[] pp_roles = new String[] { ProfilingService.PROP_CONTROLS, User.PROP_HAS_PROFILE,
			UserProfile.PROP_HAS_SUB_PROFILE, SecuritySubprofile.PROP_ROLES };
	public static String[] pp_subprofile = new String[] { ProfilingService.PROP_CONTROLS, User.PROP_HAS_PROFILE,
			UserProfile.PROP_HAS_SUB_PROFILE };

	/**
	 *
	 */
	public SecuritySubProfileRoleManagement() {
	}

	/**
	 * @param uri
	 */
	public SecuritySubProfileRoleManagement(String uri) {
		super(uri);
	}

	/** {@inheritDoc} */
	@Override
	public String getClassURI() {
		return MY_URI;
	}

}

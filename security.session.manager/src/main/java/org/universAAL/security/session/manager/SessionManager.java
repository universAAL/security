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

package org.universAAL.security.session.manager;

import java.util.Set;

import org.universAAL.ontology.location.Location;
import org.universAAL.ontology.phThing.Device;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.Session;

/**
 * Generic Interface for Session Manager
 *
 * @author amedrano
 *
 */
public interface SessionManager {

	void userAuthenticatedTo(User usr, Device dvc);

	void userDeauthenticatedFrom(User usr, Device dvc);

	void userLocationChange(User usr, Location loc);

	Set<User> validUsersForDevice(Device dvc);

	Set<User> validUsersForLocation(Location loc);

	Session getCopyOfUserSession(User usr);
}

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
package org.universAAL.security.profiles;

import org.universAAL.ontology.security.AccessType;
import org.universAAL.ontology.security.AuthorizationService;
import org.universAAL.security.ProjectActivator;

/**
 * @author amedrano
 *
 */
public class AuthorisationServiceProfile extends AuthorizationService {


    public static String MY_URI = ProjectActivator.NAMESPACE + "AuthorisationService";
	
	/**
	 * 
	 */
	public AuthorisationServiceProfile() {
	}

	/**
	 * @param uri
	 */
	public AuthorisationServiceProfile(String uri) {
		super(uri);
	}

	/**{@inheritDoc} */
	@Override
	public String getClassURI() {
		return MY_URI;
	}
	
	public static AccessType getAccessType(String uri){
		if (uri.contains("Read")){
			return AccessType.read;
		}
		if (uri.contains("Change")){
			return AccessType.change;
		}
		if (uri.contains("Add")){
			return AccessType.add;
		}
		if (uri.contains("Remove")){
			return AccessType.remove;
		}
		return null;
	}

}

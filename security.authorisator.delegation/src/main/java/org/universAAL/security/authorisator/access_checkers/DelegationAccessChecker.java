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
package org.universAAL.security.authorisator.access_checkers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.AccessRight;
import org.universAAL.ontology.security.AccessType;
import org.universAAL.ontology.security.DelegationForm;
import org.universAAL.ontology.security.Role;
import org.universAAL.ontology.security.SecuritySubprofile;
import org.universAAL.security.authorisator.access_checkers.CheckUserRoles;
import org.universAAL.security.authorisator.interfaces.AccessChecker;

/**
 * @author amedrano
 *
 */
public class DelegationAccessChecker extends CheckUserRoles implements AccessChecker {

	@Override
	public Set<AccessType> checkAccess(ModuleContext mc, User usr,
			Resource asset) {
		
		init(mc);
		
		// get the SecuritySubProfile for the user

		SecuritySubprofile ssp = getSecuritySubProfile(mc, usr);
		if (ssp == null){
			LogUtils.logInfo(mc, getClass(), "checkAccess", "No SecuritySubprofile found for user:" + usr.getURI());
			return Collections.EMPTY_SET;
		}
		
		// aggregate all the AccessRights from DelegationForms
		Object obj = ssp.getProperty(SecuritySubprofile.PROP_DELEGATED_FORMS);
		List<DelegationForm> allDelegationForms ;
		if (obj == null){
			LogUtils.logInfo(mc, getClass(), "checkAccess", "No DelegationForms found in SecuritySubprofile of user:" + usr.getURI());
			return Collections.EMPTY_SET;
		} else if (obj instanceof DelegationForm){
			allDelegationForms = new ArrayList<DelegationForm>();
			allDelegationForms.add((DelegationForm) obj);
		} else if (obj instanceof List){
			allDelegationForms = (List<DelegationForm>) obj;
		} else {
			allDelegationForms = Collections.EMPTY_LIST;
		}
		
		List<Role> roles = new ArrayList<Role>();
		
		for (DelegationForm delegationForm : allDelegationForms) {
			//check validity of each delegation form. I.E: check the signature
			if (validateDelegationForm(delegationForm)) {
				roles.addAll(getRoles(delegationForm));
			}
		}
		
		Set<AccessRight> finalAccessRights = new HashSet<AccessRight>();
		for (Role role : roles) {
			finalAccessRights.addAll(role.getAllAccessRights());
		}
		
		//match the asset with all AccessRights
		
		return matchAccessRightsWAsset(finalAccessRights, asset);
	}
	
	private boolean validateDelegationForm(DelegationForm delegationForm) {
		// TODO check the signature belongs to the Authoriser
		/*
		 * IDEA: If Delegation form is an Asset, creating DF can also be delegated! 
		 * default accessRight of DF allows for everyone to read. 
		 * A Default Role on the user allows to create its own DF. 
		 * This default Role is added if the user does not have it on the first attempt to create a DF.
		 */
		return true;
	}

	private List<Role> getRoles(DelegationForm df){
		List<Role> res;
		Object obj = df.getProperty(DelegationForm.PROP_DELEGATED_COMPETENCES);
		if (obj == null){
			return Collections.EMPTY_LIST;
		} else if (obj instanceof Role){
			res = new ArrayList<Role>();
			res.add((Role) obj);
		} else if (obj instanceof List){
			res = (List<Role>) obj;
		} else {
			return Collections.EMPTY_LIST;
		}
		return res;
	}

}

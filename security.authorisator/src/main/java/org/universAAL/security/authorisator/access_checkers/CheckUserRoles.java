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

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.universAAL.ioc.dependencies.impl.PassiveDependencyProxy;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.owl.TypeExpression;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.serialization.MessageContentSerializer;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.AccessRight;
import org.universAAL.ontology.security.AccessType;
import org.universAAL.ontology.security.Role;
import org.universAAL.ontology.security.SecuritySubprofile;
import org.universAAL.security.authorisator.CHeQuerrier;
import org.universAAL.security.authorisator.ProjectActivator;
import org.universAAL.security.authorisator.interfaces.AccessChecker;

/**
 * @author amedrano
 *
 */
public class CheckUserRoles implements AccessChecker {


	private CHeQuerrier querier;
	
	private static final String AUX_BAG_OBJECT = ProjectActivator.NAMESPACE + "auxilaryBagObject";
	private static final String AUX_BAG_PROP =  ProjectActivator.NAMESPACE + "auxilaryBagProperty";

	/**{@inheritDoc} */
	public Set<AccessType> checkAccess(ModuleContext mc, User usr,
			Resource asset) {
		
		init(mc);
		
		
		// get the SecuritySubProfile for the user
		

		SecuritySubprofile ssp = getSecuritySubProfile(mc, usr);
		if (ssp == null){
			LogUtils.logInfo(mc, getClass(), "checkAccess", "No SecuritySubprofile found for user:" + usr.getURI());
			return Collections.EMPTY_SET;
		}
		
		// aggregate all the AccessRights
		List<Role> roles = ssp.getRoles();
		Set<AccessRight> finalAccessRights = new HashSet<AccessRight>();
		for (Role role : roles) {
			finalAccessRights.addAll(role.getAllAccessRights());
		}
		
		//match the asset with all AccessRights
		
		return matchAccessRightsWAsset(finalAccessRights, asset);
	}
	
	protected void init(ModuleContext mc){
		if (querier == null){
			querier = new CHeQuerrier(mc);
		}
	}
	
	protected HashSet<AccessType> matchAccessRightsWAsset(Set<AccessRight> finalAccessRights, Resource asset){
		HashSet<AccessType> res = new HashSet<AccessType>();
		for (AccessRight ar : finalAccessRights) {
			Object te = ar.getProperty(AccessRight.MY_URI);
			if (te instanceof TypeExpression
					&& ((TypeExpression)te).hasMember(asset)){
				res.addAll(AssetDefaultAccessChecker.resolveFromValue(ar));
			}
		}
		return res;
	}

	protected SecuritySubprofile getSecuritySubProfile(ModuleContext mc, User usr){
		Object o = querier.query(CHeQuerrier.getQuery(CHeQuerrier.getResource("getSecuritySubProfileForUser.sparql"), new String[]{AUX_BAG_OBJECT,AUX_BAG_PROP,usr.getURI()}));
		SecuritySubprofile ssp;
		if (o instanceof SecuritySubprofile){
			ssp = (SecuritySubprofile) o;
		} else if (o instanceof List){
			LogUtils.logWarn(mc, getClass(), "checkAccess", "WTF mode: More than one SecuritySubprofile found for the given user: " + usr.getURI());
			ssp = (SecuritySubprofile) ((List)o).get(0);
		} else {
			LogUtils.logError(mc, getClass(), "checkAccess", "No SecuritySubprofile found for the given user: " + usr.getURI());
			return null;
		}
		return ssp;
	}
	
}

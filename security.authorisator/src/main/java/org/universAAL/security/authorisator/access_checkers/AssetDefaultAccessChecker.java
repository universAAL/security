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

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.AccessRight;
import org.universAAL.ontology.security.AccessType;
import org.universAAL.ontology.security.Asset;
import org.universAAL.security.authorisator.interfaces.AccessChecker;

/**
 * @author amedrano
 *
 */
public class AssetDefaultAccessChecker implements AccessChecker {

	/** {@inheritDoc} */
	public Set<AccessType> checkAccess(ModuleContext mc, User usr, Resource asset) {
		return resolveFromValue(asset.getProperty(Asset.PROP_HAS_DEFAULT_ACCESS));

	}

	static Set<AccessType> resolveFromValue(Object ar) {
		if (ar == null) {
			return Collections.EMPTY_SET;
		}
		Object darat = ((AccessRight) ar).getProperty(AccessRight.PROP_ACCESS_TYPE);
		if (darat == null) {
			return Collections.EMPTY_SET;
		}
		if (darat instanceof AccessType) {
			HashSet<AccessType> res = new HashSet<AccessType>();
			res.add((AccessType) darat);
			return res;
		}
		if (darat instanceof List) {
			HashSet<AccessType> res = new HashSet<AccessType>();
			res.addAll((List) darat);
			return res;
		}
		return Collections.EMPTY_SET;
	}
}

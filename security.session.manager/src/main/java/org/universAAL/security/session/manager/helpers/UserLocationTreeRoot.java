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

package org.universAAL.security.session.manager.helpers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.universAAL.ontology.location.Location;
import org.universAAL.ontology.profile.User;
import org.universAAL.security.session.manager.context.LocationChangeListener;
import org.universAAL.security.session.manager.context.SituationMonitor;


/**
 * @author amedrano
 *
 */
public class UserLocationTreeRoot implements LocationChangeListener{


    Set<UserLocationTree> children;
    
    /**
     * @param l
     */
    public UserLocationTreeRoot(SituationMonitor sm) {
	children = new HashSet<UserLocationTree>();
	addLocations(sm.getAllAvailableLocations());
	sm.addListener(this);
    }

    public Set<User> deallocateUser(User u){
	HashSet<User> affected = new HashSet<User>();
	for (UserLocationTree ult : children) {
	    affected.addAll(ult.deallocateUser(u));
	}
	return affected;
    }
    
    public UserLocationTree getMaxUser(User u) {
	for (UserLocationTree ult : children) {
	    UserLocationTree l = ult.getMaxUser(u);
	    if (l != null){
		return l;
	    }
	}
	return null;
    }

    public void addLocations(List<Location> locs){
	for (Location location : locs) {
	    UserLocationTree ult = new UserLocationTree(location);
	    UserLocationTree root = new UserLocationTree(ult.getRoot().getLocation());
	    if (!children.contains(root)){
		children.add(root);
	    }
	}
    }
    
    public void clearLocations(){
	children.clear();
    }

    /** {@ inheritDoc}	 */
    public void locationChanged(Location l) {
	UserLocationTree nult = new UserLocationTree(l);
	if (children.contains(nult)){
	    children.remove(nult);
	}
	UserLocationTree root = new UserLocationTree(nult.getRoot().getLocation());
	if (!children.contains(root)){
	    children.add(root);
	}
    }
    
}

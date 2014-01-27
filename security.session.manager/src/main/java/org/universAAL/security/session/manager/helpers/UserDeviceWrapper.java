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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.universAAL.middleware.rdf.Resource;
import org.universAAL.ontology.phThing.Device;
import org.universAAL.ontology.profile.User;

/**
 * A Wrapper to keep track of users in a certain Device.
 * @author amedrano
 *
 */
public class UserDeviceWrapper {
    
    private static final String PROP_USERS_AT_DEVICE = "http://security.universAAL.org/SessionManager#usersAtDevice";
    
    private Device dev;

    /**
     * 
     */
    public UserDeviceWrapper(Device d) {
	dev = d;
    }
    
    public Device getDevice(){
	return dev;
    }
    
    /**
     * The user set is stored as a {@link List} in the actual {@link Device}
     * instance, so this methods helps reformat that into a {@link Set}.
     * @return
     */
    public Set<User> getUserSet(){
	HashSet<User> users = new HashSet<User>();
	Object usrs = dev.getProperty(PROP_USERS_AT_DEVICE);
	if (usrs instanceof User){
	    users.add((User) usrs);
	} 
	if (usrs instanceof Collection){
	    users.addAll((Collection) usrs);
	}
	return users;
    }
    
    /**
     * Complement to {@link UserDeviceWrapper#getUserSet()}.
     * @param users
     */
    public void setUserSet(Set<User> users){
	if (users.size() == 0){
	    dev.changeProperty(PROP_USERS_AT_DEVICE, null);
	} 
	if (users.size() == 1){
	    Iterator<User> it = users.iterator();
	    dev.changeProperty(PROP_USERS_AT_DEVICE, it.next());
	}
	else {
	    dev.changeProperty(PROP_USERS_AT_DEVICE, new ArrayList<User>(users));
	}
    }
    
    /**
     * Remove a single user from this {@link Device}.
     * @param u
     */
    public void removeUser(User u){
	Set<User> users = getUserSet();
	users.remove(u);
	setUserSet(users);
    }
    
    /**
     * Add a single {@link User} to this {@link Device}.
     * @param u
     */
    public void addUser(User u){
	Set<User> users = getUserSet();
	if (users.size() == 0){
	    dev.changeProperty(PROP_USERS_AT_DEVICE, u);
	} else {
	    users.add(u);
	    dev.changeProperty(PROP_USERS_AT_DEVICE, new ArrayList<User>(users));
	}
    }

    public UserDeviceWrapper getParent(){
	Object parent = dev.getProperty(Device.PROP_PART_OF);
	if (parent instanceof Device){
	    return new UserDeviceWrapper((Device) parent);
	}
	return null;
    }
    
    public UserDeviceWrapper getRoot(){
	UserDeviceWrapper parent = getParent();
	if (parent == null){
	    return this;
	}else {
	    return parent.getRoot();
	}
    }
}

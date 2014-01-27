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

import org.universAAL.ontology.location.Location;
import org.universAAL.ontology.profile.User;

/**
 * Extends {@link LocationTreeWrapper} to add a {@link Set} of {@link User}s to
 * each node in the tree.
 * In addition it manages the Allocation and Deallocation of users in the {@link Location} tree.
 * @author amedrano
 *
 */
public class UserLocationTree extends LocationTreeWrapper {

    
    private static final String PROP_USERS_AT_LOCATION = "http://security.universAAL.org/SessionManager#usersAtLocation";

    /**
     * Model the given {@link Location}.
     * @param l
     */
    public UserLocationTree(Location l) {
	super(l);
    }
    
    /**
     * Utility method to transform {@link LocationTreeWrapper}s from
     * {@link LocationTreeWrapper#getChildren()} into {@link UserLocationTree}.
     * @return
     */
    private Set<UserLocationTree> getUserChildren(){
	Set<LocationTreeWrapper> children = super.getChildren();
	HashSet<UserLocationTree> ultChildren = new HashSet<UserLocationTree>();
	for (LocationTreeWrapper ltw : children) {
	    ultChildren.add(new UserLocationTree(ltw.getLocation()));
	}
	return ultChildren;
    }
    
    /**
     * Utility method to transform {@link LocationTreeWrapper}s from
     * {@link LocationTreeWrapper#getParent()} into {@link UserLocationTree}.
     * @return
     */
    private UserLocationTree getUserParent(){
	LocationTreeWrapper parent = getParent();
	if (parent != null){
	    return new UserLocationTree(parent.loc);
	}
	return null;
    }
    
    /**
     * The user set is stored as a {@link List} in the actual {@link Location}
     * instance, so this methods helps reformat that into a {@link Set}.
     * @return
     */
    public Set<User> getUserSet(){
	HashSet<User> users = new HashSet<User>();
	Object usrs = loc.getProperty(PROP_USERS_AT_LOCATION);
	if (usrs instanceof User){
	    users.add((User) usrs);
	} 
	if (usrs instanceof Collection){
	    users.addAll((Collection) usrs);
	}
	return users;
    }
    
    /**
     * Complement to {@link UserLocationTree#getUserSet()}.
     * @param users
     */
    public void setUserSet(Set<User> users){
	if (users.size() == 0){
	    loc.changeProperty(PROP_USERS_AT_LOCATION, null);
	} 
	if (users.size() == 1){
	    Iterator<User> it = users.iterator();
	    loc.changeProperty(PROP_USERS_AT_LOCATION, it.next());
	}
	else {
	    loc.changeProperty(PROP_USERS_AT_LOCATION, new ArrayList<User>(users));
	}
    }
    
    /**
     * Add a single {@link User} to this {@link Location}.
     * @param u
     */
    public void addUser(User u){
	Set<User> users = getUserSet();
	if (users.size() == 0){
	    loc.changeProperty(PROP_USERS_AT_LOCATION, u);
	} else {
	    users.add(u);
	    loc.changeProperty(PROP_USERS_AT_LOCATION, new ArrayList<User>(users));
	}
    }
    
    /**
     * Remove the {@link User} from the whole {@link Location} tree.
     * There may be users affected by this movement, since they might be alone now
     * that the other user is deallocated. 
     * @param u the user to be removed.
     * @return the {@link Set} of {@link User}s affected.
     */
    public Set<User> deallocateUser(User u){
	if (!isRoot()){
	    return ((UserLocationTree) getRoot()).deallocateUser(u);
	}
	else {
	    Set<User> affected = new HashSet<User>();
	    Set<User> usrs = getUserSet();
	    if (usrs.contains(u)){
		usrs.remove(u);
		if (usrs.size() == 1){
		    Iterator<User> it = usrs.iterator();
		    affected.add(it.next());
		}
		setUserSet(usrs);
	    }
	    for (UserLocationTree tn : getUserChildren()) {
		affected.addAll(tn.deallocateUser(u));
	    }
	    return affected;
	}
    }
    
    /**
     * Used as delegation method for {@link UserLocationTree#allocateUser(User)}.
     * @param u the user to add at this {@link Location}.
     * @param recursively whether all the children should be marked too.
     * @return all the affected users by this making.
     */
    private Set<User> markUserHere(User u, boolean recursively){
	Set<User> affected = new HashSet<User>();
	Set<User> usrs = getUserSet();
	if (!usrs.contains(u)){
	    if (usrs.size() == 1){
		Iterator<User> it = usrs.iterator();
		affected.add(it.next());
	    }
	    addUser(u);
	}
	if (recursively){
	    for (UserLocationTree tn : getUserChildren()) {
		affected.addAll(tn.markUserHere(u, recursively));
	    }
	}
	return affected;
    }
    
    /**
     * Allocate a user in the {@link Location} tree, this means the user is logically 
     * located in all of the parent locations of this location.
     * But all children locations must be marked too.
     * @param u the allocated user.
     * @return the affected {@link User}s by this allocation.
     */
    public Set<User> allocateUser(User u){
	Set<User> affected = new HashSet<User>();
	//Mark user at this location and children of this location
	affected.addAll(markUserHere(u, true));
	//Mark on all parent locations of this location
	UserLocationTree p = getUserParent();
	while(p != null){
	    affected.addAll(p.markUserHere(u,false));
	    p = p.getUserParent();
	}
	
	return affected;
    }

    /**
     * Calculate the uppermost {@link Location} in which the {@link User} is alone.
     * @param u
     * @return the {@link UserLocationTree} where the user is alone,
     * null if it is not in the location tree, or she/he is not alone anywhere.
     * TODO add delegation logic here.
     */
    public UserLocationTree getMaxUser(User u){
	Set<User> usrs = getUserSet();
	if (usrs.contains(u)
		&& usrs.size() == 1){
	    //if he is alone in this node then this is it's max
	    return this;
	}
	else {
	    //he is not alone.
	    Set<UserLocationTree> chld = getUserChildren();
	    List<UserLocationTree> childrenWithThisUser 
	    	= new ArrayList<UserLocationTree>();
	    for (UserLocationTree c : chld) {
		//get all children where the user is.
		if(c.getUserChildren().contains(u)){
		    childrenWithThisUser.add(c);
		}
	    }
	    int size = childrenWithThisUser.size();
	    if (size == 0 || size > 1){
		/*
		 *  if there are no remaining children, 
		 *  then this is the node
		 *  if  it has more than one children,
		 *  then that means that each children will report a different 
		 *  max. The user might not be alone, but it is the most generic
		 *  location registered.
		 */
		return usrs.contains(u)? this: null;
		// it will be very strange if it returns null:
		// only case-> the user is not in the tree at all.
	    }
	    if (size == 1){
		/*
		 * if there is only one node, then investigate it.
		 */
		return childrenWithThisUser.get(0).getMaxUser(u);
	    }
	}
	//it is not alone
	return null;
    }
}

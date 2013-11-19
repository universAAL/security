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

package org.security.session.manager.impl;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.security.session.manager.SessionManager;
import org.security.session.manager.context.SessionPublisher;
import org.security.session.manager.context.SituationMonitor;
import org.security.session.manager.helpers.UserDeviceWrapper;
import org.security.session.manager.helpers.UserLocationTree;
import org.security.session.manager.helpers.UserLocationTreeRoot;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.util.Constants;
import org.universAAL.ontology.location.Location;
import org.universAAL.ontology.phThing.Device;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.DeviceBoundSession;
import org.universAAL.ontology.security.LocationBoundSession;
import org.universAAL.ontology.security.Session;

/**
 * @author amedrano
 *
 */
public class SessionManagerImpl implements SessionManager {

    private static Session INVALID = 
	    (Session) Session.getInstance(Session.MY_URI, Session.INSTANCE_INVALID_SESSION);
    
    
    /**
     * The module context.
     */
    private ModuleContext owner;

    /**
     * The publisher of {@link Session}s.
     */
    private SessionPublisher publisher;
    
    /**
     * The {@link SituationMonitor}.
     */
    private SituationMonitor monitor;
    
    /**
     * The main map for sessions, mapping user URI 
     * to their current Session.
     */
    private Map<User, Session> sessions;
    
    /**
     * The Last state of the userLocation.
     */
    private Map<User, Location> userLocation; 

    /**
     * The {@link Location} tree virtual root. 
     */
    private UserLocationTreeRoot locationRoot;
    
    /**
     * constructor
     */
    public SessionManagerImpl(ModuleContext mc, SituationMonitor sc, SessionPublisher publisher) {
	monitor = sc;
	this.publisher = publisher;
	owner = mc;
	sessions = new HashMap<User, Session>();
	userLocation = new HashMap<User, Location>();
	locationRoot = new UserLocationTreeRoot(monitor);
    }

    /** {@ inheritDoc}	 */
    public void userAuthenticatedTo(User usr, Device dvc) {
	Session s = null;
	if (canLocationBoundedSessionBeIssued(usr,dvc)){
	    /*
	     * if there is a location then, uplift to the location 
	     * where there are no other users.
	     */
	    
	    s = new LocationBoundSession(constructSessionURI(usr));
	    s.setProperty(LocationBoundSession.PROP_BOUNDED_LOCATION, 
		    locationRoot.getMaxUser(usr).getLocation());
	}
	else {
	    /*
	     * if there is not a location of the authentication 
	     * create a device bounded session for the most parent device.
	     */
	    s = new DeviceBoundSession(constructSessionURI(usr));
	    Device d = monitor.getInternalStateOf(dvc);
	    UserDeviceWrapper udw = new UserDeviceWrapper(d);
	    s.setProperty(DeviceBoundSession.PROP_BOUNDED_DEVICE, udw.getRoot().getDevice());
	}
	if (s != null){
//	    s.setExpiration(date); //TODO when? add a watchdog
	    //add it to the map
	    sessions.put(usr, s);
	    //publish the uplifted session. 
	    publisher.updateSession(usr,s);
	}

    }

    /**
     * @param usr
     * @return
     */
    private String constructSessionURI(User usr) {
	return Constants.uAAL_MIDDLEWARE_LOCAL_ID_PREFIX + "sessionFor" + usr.getLocalName();
    }

    /**
     * @param usr
     * @param dvc
     * @return
     */
    private boolean canLocationBoundedSessionBeIssued(User usr, Device dvc) {
	/*
	 * find the location of the authentication
	 */
	Location loc = monitor.locationOf(dvc);
	Location uLoc = userLocation.get(usr);
	//TODO compare, check that locations are compatible
	return (loc != null && uLoc != null);
    }

    /** {@ inheritDoc}	 */
    public void userDeauthenticatedFrom(User usr, Device dvc) {
	// TODO Discussion: user loggin of in one device means it logs of in the space?
	sessions.put(usr, INVALID);
	publisher.updateSession(usr, INVALID);
    }

    /** {@ inheritDoc}	 */
    public void userLocationChange(User usr, Location loc) {
	Location iLoc = monitor.getInternalStateOf(loc);
	userLocation.put(usr, iLoc);
	//check if any user session has to be updated.
	UserLocationTree ult = new UserLocationTree(iLoc);
	Set<User> affected = locationRoot.deallocateUser(usr);
	affected.addAll(ult.allocateUser(usr));
	affected.add(usr);
	for (User user : affected) {
	    Session us = sessions.get(user);
	    if (us instanceof LocationBoundSession) {
		UserLocationTree mu = locationRoot.getMaxUser(user);
		if (!mu.getLocation().equal(us.getProperty(LocationBoundSession.PROP_BOUNDED_LOCATION))){
		    us.changeProperty(LocationBoundSession.PROP_BOUNDED_LOCATION, mu.getLocation());
		    sessions.put(user, us);
		    publisher.updateSession(user, us);
		}
	    }
	}
	//check if DeviceBoundSession can be uplifted to a LocationBoundSession.
	Session s = sessions.get(usr);
	if (s instanceof DeviceBoundSession) {
	    Device d = (Device) s.getProperty(DeviceBoundSession.PROP_BOUNDED_DEVICE);
	    if (canLocationBoundedSessionBeIssued(usr, d)) {
		userAuthenticatedTo(usr, d);
	    }
	}
    }

    /** {@ inheritDoc}	 */
    public Set<User> validUsersForDevice(Device dvc) {
	Device d = monitor.getInternalStateOf(dvc);
	Location dLoc = monitor.locationOf(d);
	Set<User> users = new HashSet<User>();
	if (dLoc != null) {
	    users.addAll(new UserLocationTree(dLoc).getUserSet());
	}
	//add the users with DeviceBoundSessions in this device.
	users.addAll(new UserDeviceWrapper(d).getUserSet());
	return users;
    }

    /** {@ inheritDoc}	 */
    public Set<User> validUsersForLocation(Location loc) {
	Set<User> users =new UserLocationTree(loc).getUserSet();
	//add the users with DeviceBoundSessions in the devices in this location.
	// TODO Discussion: does this make sense?
	List<Device> devs = monitor.devicesInLocation(loc);
	for (Device d : devs) {
	    users.addAll(new UserDeviceWrapper(d).getUserSet());
	}
	return users;
    }

    /** {@ inheritDoc}	 */
    public Session getCopyOfUserSession(User usr) {
	Session s = sessions.get(usr.getURI());
	if (s == null){
	    //A new user not previously managed has entered the space?
	    LogUtils.logWarn(owner, getClass(), "getCopyOfUserSession", 
		    "A copy of an un managed user has been requested, " +
	    		"this might mean there is some security breach attemp");
	    sessions.put(usr, INVALID);
	    s = INVALID;
	}
    	return SessionPublisher.filteredCopy(s);
    }

}

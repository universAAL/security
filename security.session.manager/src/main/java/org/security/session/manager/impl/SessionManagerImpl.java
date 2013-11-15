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
import java.util.Map;
import java.util.Set;

import org.security.session.manager.SessionManager;
import org.security.session.manager.context.SessionPublisher;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.context.ContextEvent;
import org.universAAL.ontology.location.Location;
import org.universAAL.ontology.phThing.Device;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.DeviceBoundSession;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.security.Session;

/**
 * @author amedrano
 *
 */
public class SessionManagerImpl implements SessionManager {

    private static Session INVALID = 
	    (Session) Session.getInstance(Session.MY_URI, Session.INSTANCE_INVALID_SESSION);
    
    SituationCaller caller;
    
    /**
     * The main map for sessions, mapping user URI 
     * to their current Session.
     */
    Map<User, Session> sessions;

    /**
     * 
     */
    Map<Location, Set<User>> locationMap;
    
    private ModuleContext owner;

    private SessionPublisher publisher;
    
    /**
     * constructor
     */
    public SessionManagerImpl(ModuleContext mc, SituationCaller sc, SessionPublisher publisher) {
	caller = sc;
	this.publisher = publisher;
	owner = mc;
	sessions = new HashMap<User, Session>();
    }

    /** {@ inheritDoc}	 */
    public void userAuthenticatedTo(User usr, Device dvc) {
	Session s = null;
	/*
	 * find the location of the authentication
	 */
	Location loc = caller.locationOf(dvc);
	if (loc != null){
	    /*
	     * if there is a location then, uplift to the location 
	     * where there are no other users.
	     */
	    
	}
	else {
	    /*
	     * if there is not a location of the authentication 
	     * create a device bounded session for the most parent device.
	     */
	    s = new DeviceBoundSession();
//	    s.setExpiration(date); //TODO when? add a watchdog
	    s.setProperty(DeviceBoundSession.PROP_BOUNDED_DEVICE, caller.superParentOf(dvc));
	}
	if (s != null){
	    //add it to the map
	    sessions.put(usr, s);
	    //publish the uplifted session. //TODO remove private properties in copies.
//	    usr.changeProperty(SecurityOntology.PROP_SESSION, s.copy(false));
//	    publisher.publish(new ContextEvent(usr, SecurityOntology.PROP_SESSION));
	}

    }

    /** {@ inheritDoc}	 */
    public void userDeauthenticatedFrom(User usr, Device dvc) {
	// TODO Auto-generated method stub

    }

    /** {@ inheritDoc}	 */
    public void userLocationChange(User usr, Location loc) {
	// TODO Auto-generated method stub

    }

    /** {@ inheritDoc}	 */
    public Set<User> validUsersForDevice(Device dvc) {
	// TODO Auto-generated method stub
	return null;
    }

    /** {@ inheritDoc}	 */
    public Set<User> validUsersForLocation(Location loc) {
	// TODO Auto-generated method stub
	return null;
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
	}
    	return (Session) sessions.get(usr.getURI()).copy(false);
    }

}

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

package org.universAAL.security.session.manager.impl;

import java.util.ArrayList;
import java.util.List;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.context.ContextEvent;
import org.universAAL.middleware.context.ContextEventPattern;
import org.universAAL.middleware.context.ContextSubscriber;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.ontology.location.Location;
import org.universAAL.ontology.phThing.Device;
import org.universAAL.security.session.manager.context.LocationChangeListener;
import org.universAAL.security.session.manager.context.SituationMonitor;
import org.universAAL.security.session.manager.helpers.CHeQuery;
import org.universAAL.security.session.manager.helpers.LocationTreeWrapper;

/**
 * @author amedrano
 *
 */
public class SituationMonitorImpl extends ContextSubscriber implements SituationMonitor {
    
    /**
     * 
     */
    private static final String AUX_PROP = "http://security.universAAL.org/Security#auxProp";

    private List<Location> locations;
    
    private List<Device> devices;

    private List<LocationChangeListener> listeners;
    
    /**
     * 
     */
    public SituationMonitorImpl(ModuleContext mc) {
	super(mc, getPatterns());
	listeners = new ArrayList<LocationChangeListener>();
	initializeLocations();
	initializeDevices();
    }

    /**
     * @return
     */
    private static ContextEventPattern[] getPatterns() {

	ContextEventPattern[] patterns = new ContextEventPattern[4];
	ContextEventPattern cep = new ContextEventPattern();
	cep.addRestriction(MergedRestriction
			.getAllValuesRestriction(ContextEvent.PROP_RDF_OBJECT, Device.MY_URI));
	patterns[0] = cep;
	
	cep = new ContextEventPattern();
	cep.addRestriction(MergedRestriction
			.getAllValuesRestriction(ContextEvent.PROP_RDF_SUBJECT, Device.MY_URI));
	patterns[1] = cep;
	
	cep = new ContextEventPattern();
	cep.addRestriction(MergedRestriction
			.getAllValuesRestriction(ContextEvent.PROP_RDF_OBJECT, Location.MY_URI));
	patterns[2] = cep;
	
	cep = new ContextEventPattern();
	cep.addRestriction(MergedRestriction
			.getAllValuesRestriction(ContextEvent.PROP_RDF_SUBJECT, Location.MY_URI));
	patterns[3] = cep;
	return patterns;
    }

    /**
     * Service call to query all locations in CHe.
     * 
     */
    private void initializeLocations() {
	if (locations == null){
            locations = new ArrayList<Location>();
	}
        Object res = new CHeQuery(owner).query("getLocations.sparql", null);
        if (res == null){
            return;
        }
        if (res instanceof Resource){
            res = ((Resource)res).getProperty(AUX_PROP);
        }
        if (res == null){
            return;
        }
        if (res instanceof Location){
            locations.add((Location) res);
            return;
        }
        if (res instanceof List){
            locations.addAll((List) res);
        }
    }

    /**
     * Service call to query all Devices in CHe.
     */
    private void initializeDevices() {
	if (devices == null){
	    devices = new ArrayList<Device>();
	}
        Object res = new CHeQuery(owner).query("getDevices.sparql", null);
        if (res == null){
            return;
        }
        if (res instanceof Resource){
            res = ((Resource)res).getProperty(AUX_PROP);
        }
        if (res == null){
            return;
        }
        if (res instanceof Device){
            devices.add((Device) res);
            return;
        }
        if (res instanceof List){
            devices.addAll((List) res);
        }
        
    }

    /** {@ inheritDoc}	 */
    public Location locationOf(Device d) {
	if(d.getLocation() != null){
	    return d.getLocation();
	}
	// TODO query CHe see if change was done via service call.
	Object res = new CHeQuery(owner).query("getResource", new String[]{d.getURI()});
	if (res != null && res instanceof Device){
	    devices.remove(d);
	    devices.add((Device)res);
	    return ((Device)res).getLocation();
	}
	return null;
    }

    /** {@ inheritDoc}	 */
    public Location getInternalStateOf(Location l) {
	for (Location il : locations) {
	    if (il.equals(l)){
		return il;
	    }
	}
	// unseen location 
	locations.add(l);
	return l;
    }

    /** {@ inheritDoc}	 */
    public Device getInternalStateOf(Device d) {
	for (Device id : devices) {
	    if (id.equals(d)){
		return id;
	    }
	}
	// unseen device
	devices.add(d);
	return d;
    }

    /** {@ inheritDoc}	 */
    public List<Location> getAllAvailableLocations() {
	if (locations == null){
	    initializeLocations();
	}
	return locations;
    }

    /** {@ inheritDoc}	 */
    public List<Device> devicesInLocation(Location loc) {
	List<Device> devs = new ArrayList<Device>();
	for (Device device : devices) {
	    if (isContained(locationOf(device), loc)){
		devs.add(device);
	    }
	}
	return devs;
    }

    /**
     * @param locationOf
     * @param loc
     * @return
     */
    private boolean isContained(Location loc, Location inLoc) {
	if (loc == null || inLoc == null)
	    return false;
	if (loc.equals(inLoc)){
	   return true; 
	}
	LocationTreeWrapper ltw = new LocationTreeWrapper(loc);
	if (ltw.getParent() == null){
	    return false;
	}
	return isContained(ltw.getParent().getLocation(), inLoc);
    }

    /** {@ inheritDoc}	 */
    public void addListener(LocationChangeListener lcl) {
	listeners.add(lcl);
    }

    /** {@ inheritDoc}	 */
    public void removeListener(LocationChangeListener lcl) {
	listeners.remove(lcl);
    }

    /** {@ inheritDoc}	 */
    public void close() {
	listeners.clear();
	locations.clear();
	devices.clear();
	super.close();
    }

    /** {@ inheritDoc}	 */
    @Override
    public void communicationChannelBroken() {
	// nothing	
    }

    /** {@ inheritDoc}	 */
    @Override
    public void handleContextEvent(ContextEvent event) {
	Resource subject = event.getRDFSubject();
	Object obj = event.getRDFObject();
	if (subject instanceof Device){
	    if (!devices.contains(subject)){
		devices.add((Device) subject);
	    }
	}
	if (obj instanceof Device){
	    if (!devices.contains(obj)){
		devices.add((Device) obj);
	    }
	}
	if (subject instanceof Location){
	    if (!locations.contains(subject)){
		locations.add((Location) subject);
	    }
	    // relay listeners
	    for (LocationChangeListener l : listeners) {
		l.locationChanged((Location) subject);
	    }
	}
	if (obj instanceof Location){
	    if (!locations.contains(obj)){
		locations.add((Location) obj);
	    }
	    // relay listeners
	    for (LocationChangeListener l : listeners) {
		l.locationChanged((Location) obj);
	    }
	}
    }

}

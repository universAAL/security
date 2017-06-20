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
package org.universAAL.security.authorisator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.universAAL.ioc.dependencies.impl.PassiveDependencyProxy;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.owl.ManagedIndividual;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.serialization.MessageContentSerializer;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.ServiceCall;
import org.universAAL.middleware.service.ServiceCallee;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.process.ProcessOutput;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.AccessRight;
import org.universAAL.ontology.security.AccessType;
import org.universAAL.ontology.security.Role;
import org.universAAL.ontology.security.SecuritySubprofile;
import org.universAAL.security.authorisator.access_checkers.AssetDefaultAccessChecker;
import org.universAAL.security.authorisator.access_checkers.CheckUserRoles;
import org.universAAL.security.authorisator.interfaces.AccessChecker;
import org.universAAL.security.authorisator.profiles.AuthorisationServiceProfile;

/**
 * @author amedrano
 * 
 */
public class AuthorisatorCallee extends ServiceCallee {

    private static final String AUX_BAG_OBJECT = ProjectActivator.NAMESPACE
	    + "auxilaryBagObject";
    private static final String AUX_BAG_PROP = ProjectActivator.NAMESPACE
	    + "auxilaryBagProperty";
    private static List<AccessChecker> checkers = new ArrayList<AccessChecker>();
    private PassiveDependencyProxy<MessageContentSerializer> serializer;
    private CHeQuerrier query;

    /**
     * @param context
     * @param realizedServices
     */
    public AuthorisatorCallee(ModuleContext context,
	    ServiceProfile[] realizedServices) {
	super(context, realizedServices);
	serializer = new PassiveDependencyProxy<MessageContentSerializer>(
		context,
		new Object[] { MessageContentSerializer.class.getName() });
	query = new CHeQuerrier(owner);
	registerChecker(new AssetDefaultAccessChecker());
	registerChecker(new CheckUserRoles());
    }

    /** {@inheritDoc} */
    @Override
    public void communicationChannelBroken() {

    }

    /** {@inheritDoc} */
    @Override
    public ServiceResponse handleCall(ServiceCall call) {
	String callURI = call.getProcessURI();
	if (callURI.contains(ProjectActivator.ADD_ROLE_SP)) {
	    SecuritySubprofile ssp = (SecuritySubprofile) call
		    .getInputValue(ProjectActivator.SUBPROFILE);
	    Role r = (Role) call.getInputValue(ProjectActivator.ROLE);

	    ssp.addrole(r);

	    // update SSP role prop in CHe
	    if (addTriple(ssp, SecuritySubprofile.PROP_ROLES))
		return new ServiceResponse(CallStatus.succeeded);
	    else
		return new ServiceResponse(CallStatus.serviceSpecificFailure);
	}
	if (callURI.contains(ProjectActivator.REMOVE_ROLE_SP)) {
	    SecuritySubprofile ssp = (SecuritySubprofile) call
		    .getInputValue(ProjectActivator.SUBPROFILE);
	    Role r = (Role) call.getInputValue(ProjectActivator.ROLE);

	    List roles = ssp.getRoles();
	    roles.remove(r);
	    ssp.changeProperty(SecuritySubprofile.PROP_ROLES, roles);

	    // update SSP role prop in CHe
	    if (removeTriple(ssp, SecuritySubprofile.PROP_ROLES, r))
		return new ServiceResponse(CallStatus.succeeded);
	    else
		return new ServiceResponse(CallStatus.serviceSpecificFailure);

	}
	if (callURI.contains(ProjectActivator.ADD_ROLE_ROLE)) {
	    Role r = (Role) call.getInputValue(ProjectActivator.ROLE);
	    Role sr = (Role) call.getInputValue(ProjectActivator.SUBROLE);

	    r.addSubRole(sr);

	    // update Role subroles in CHe
	    if (addTriple(r, Role.PROP_SUB_ROLES))
		return new ServiceResponse(CallStatus.succeeded);
	    else
		return new ServiceResponse(CallStatus.serviceSpecificFailure);
	}
	if (callURI.contains(ProjectActivator.REMOVE_ROLE_ROLE)) {
	    Role r = (Role) call.getInputValue(ProjectActivator.ROLE);
	    Role sr = (Role) call.getInputValue(ProjectActivator.SUBROLE);

	    r.removeSubRole(sr);
	    // XXX make it recursive?
	    // update Role subroles in CHe
	    if (removeTriple(r, Role.PROP_SUB_ROLES, sr))
		return new ServiceResponse(CallStatus.succeeded);
	    else
		return new ServiceResponse(CallStatus.serviceSpecificFailure);

	}
	if (callURI.contains(ProjectActivator.CHANGE_ROLE)) {
	    Role r = (Role) call.getInputValue(ProjectActivator.ROLE);

	    // update AR in CHe
	    if (updateObject(r))
		return new ServiceResponse(CallStatus.succeeded);
	    else
		return new ServiceResponse(CallStatus.serviceSpecificFailure);
	}
	if (callURI.contains(ProjectActivator.GET_ROLES)) {
	    Object ret = getAllObjectsOfType(Role.MY_URI);
	    if (ret != null) {
		ProcessOutput po = new ProcessOutput(ProjectActivator.ROLE, ret);
		ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
		sr.addOutput(po);
		return sr;
	    } else {
		return new ServiceResponse(CallStatus.serviceSpecificFailure);
	    }
	}
	if (callURI.contains(ProjectActivator.ADD_AR_ROLE)) {
	    Role r = (Role) call.getInputValue(ProjectActivator.ROLE);
	    AccessRight ar = (AccessRight) call
		    .getInputValue(ProjectActivator.ACCESS_RIGHT);

	    r.addAccessRight(ar);

	    // update Role accessRights in CHe
	    if (addTriple(r, Role.PROP_HAS_ACCESS_RIGHTS))
		return new ServiceResponse(CallStatus.succeeded);
	    else
		return new ServiceResponse(CallStatus.serviceSpecificFailure);
	}
	if (callURI.contains(ProjectActivator.REMOVE_AR_ROLE)) {
	    Role r = (Role) call.getInputValue(ProjectActivator.ROLE);
	    AccessRight ar = (AccessRight) call
		    .getInputValue(ProjectActivator.ACCESS_RIGHT);

	    r.removeAccessRight(ar);

	    // update Role accessRights in CHe
	    if (removeTriple(r, Role.PROP_HAS_ACCESS_RIGHTS, ar))
		return new ServiceResponse(CallStatus.succeeded);
	    else
		return new ServiceResponse(CallStatus.serviceSpecificFailure);
	}
	if (callURI.contains(ProjectActivator.CHANGE_AR)) {
	    AccessRight ar = (AccessRight) call
		    .getInputValue(ProjectActivator.ACCESS_RIGHT);

	    // update AR in CHe
	    if (updateObject(ar))
		return new ServiceResponse(CallStatus.succeeded);
	    else
		return new ServiceResponse(CallStatus.serviceSpecificFailure);
	}
	if (callURI.contains(ProjectActivator.GET_AR)) {
	    Object ret = getAllObjectsOfType(AccessRight.MY_URI);
	    if (ret != null) {
		ProcessOutput po = new ProcessOutput(
			ProjectActivator.ACCESS_RIGHT, ret);
		ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
		sr.addOutput(po);
		return sr;
	    } else {
		return new ServiceResponse(CallStatus.serviceSpecificFailure);
	    }
	}
	if (callURI.contains("check")) {

	    Resource usr = (User) call.getInputValue(ProjectActivator.USER);
	    if (usr == null) {
		usr = call.getInvolvedUser();
	    }
	    if (usr == null
		    || !ManagedIndividual.checkMembership(User.MY_URI, usr)) {
		return new ServiceResponse(CallStatus.denied);
	    }

	    Resource asset = (Resource) call
		    .getInputValue(ProjectActivator.ASSET);
	    Set<AccessType> compiledAccess = new HashSet<AccessType>();
	    for (AccessChecker ac : checkers) {
		compiledAccess.addAll(ac.checkAccess(owner, (User) usr, asset));
	    }

	    AccessType requested = AuthorisationServiceProfile
		    .getAccessType(callURI);
	    LogUtils.logDebug(
		    owner,
		    getClass(),
		    "handleCall",
		    "Checking user AccesRights: "
			    + Arrays.toString(compiledAccess.toArray())
			    + "\n with type:" + requested.getURI());
	    if (compiledAccess.contains(requested)) {
		LogUtils.logDebug(owner, getClass(), "handleCall",
			"Access Granted!");
		return new ServiceResponse(CallStatus.succeeded);
	    } else {
		LogUtils.logDebug(owner, getClass(), "handleCall",
			"Access Denied!");
		return new ServiceResponse(CallStatus.denied);
	    }
	}

	return new ServiceResponse(CallStatus.noMatchingServiceFound);
    }

    public static Resource copy(Resource r, String newURI) {
	Resource copy = Resource.getResource(r.getType(), newURI);
	if (copy == null)
	    copy = new Resource(newURI);
	for (Enumeration e = r.getPropertyURIs(); e.hasMoreElements();) {
	    String key = (String) e.nextElement();
	    copy.changeProperty(key, r.getProperty(key));
	}
	return copy;
    }

    /**
     * Sends a new triple (or more if value is complex) to the SPARQL backend.
     * 
     * @param root
     * @param prop
     * @return
     */
    private boolean addTriple(Resource root, String prop) {
	String serialization = serializer.getObject().serialize(
		removeOtherProps(root, prop));

	String[] split = CHeQuerrier.splitPrefixes(serialization);

	String prefixes = split[0];
	String serialValue = split[1];

	String resp = query.unserialisedQuery(CHeQuerrier.getQuery(
		CHeQuerrier.getResource("addTriple.sparql"), new String[] {
			prefixes, serialValue }));
	return resp != null && !resp.isEmpty()
		&& !resp.toLowerCase().equals("false");
    }

    /**
     * Removes a single triple from the SPARQL backend.
     * 
     * @param root
     * @param prop
     * @return
     */
    private boolean removeTriple(Resource root, String prop, Resource value) {
	if (value == null) {
	    // Needed for triple remove
	    return false;
	}

	String resp = query.unserialisedQuery(CHeQuerrier.getQuery(
		CHeQuerrier.getResource("removeTriple.sparql"), new String[] {
			root.getURI(), prop, value.getURI() }));
	return resp != null && !resp.isEmpty()
		&& !resp.toLowerCase().equals("false");
    }

    private Resource removeOtherProps(Resource r, String prop) {
	// create a copy and remove every other property
	Resource copy = r.copy(false);
	Enumeration en = copy.getPropertyURIs();
	while (en.hasMoreElements()) {
	    String p = (String) en.nextElement();
	    if (!p.equals(prop)) {
		copy.changeProperty(p, null);
	    }
	}

	// remove list in case of list of 1
	Object pval = copy.getProperty(prop);
	if (pval instanceof List && ((List) pval).size() == 1) {
	    pval = ((List) pval).get(0);
	    copy.changeProperty(prop, pval);
	}
	if (pval instanceof Resource) {
	    ((Resource) pval).unliteral();
	}

	return copy;
    }

    /**
     * Update a full object in the data base.
     * 
     * @param r
     *            the new object (replacing old one with same URI)
     * @return true iif the object is updated.
     */
    private boolean updateObject(Resource r) {

	String serialization = serializer.getObject().serialize(r);

	String[] split = CHeQuerrier.splitPrefixes(serialization);

	String prefixes = split[0];
	String serialValue = split[1];
	String resp = query.unserialisedQuery(CHeQuerrier.getQuery(
		CHeQuerrier.getResource("updateFullObject.sparql"),
		new String[] { prefixes, r.getURI(), serialValue }));
	return resp != null && !resp.isEmpty()
		&& !resp.toLowerCase().equals("false");
    }

    /**
     * Query the database to gather all objects of the same class URI.
     * 
     * @param classuri
     *            The class of the objects to be collected.
     * @return a list, or the single object stored in the data base with the
     *         requested class.
     */
    private Object getAllObjectsOfType(String classuri) {
	List val = new ArrayList();
	Object o = query.query(CHeQuerrier.getQuery(
		CHeQuerrier.getResource("getObjectType.sparql"), new String[] {
			AUX_BAG_OBJECT, AUX_BAG_PROP, classuri }));
	if (o instanceof Resource) {
	    o = ((Resource) o).getProperty(AUX_BAG_PROP);
	    if (o instanceof List) {
		List ol = (List) o;
		for (Object res : ol) {
		    val.add(query.getFullResourceGraph(((Resource) o).getURI()));
		}
		return val;
	    } else {
		return query.getFullResourceGraph(((Resource) o).getURI());
	    }
	} else {
	    LogUtils.logError(owner, getClass(), "getAllObjectsOfType",
		    "Wrong querry response, should get a Resource and we didn't");
	    return null;
	}
    }

    public static void registerChecker(AccessChecker ac) {
	synchronized (checkers) {
	    checkers.add(ac);
	}
    }

    public static void unregisterChecker(AccessChecker ac) {
	synchronized (checkers) {
	    checkers.remove(ac);
	}
    }

    public static void unregisterChecker(Class acc) {
	for (AccessChecker ac : checkers) {
	    if (ac.getClass().equals(acc)) {
		unregisterChecker(ac);
	    }
	}
    }
}

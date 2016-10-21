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

import org.universAAL.middleware.bus.junit.BusTestCase;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.ontology.cryptographic.CryptographicOntology;
import org.universAAL.ontology.location.LocationOntology;
import org.universAAL.ontology.phThing.PhThingOntology;
import org.universAAL.ontology.profile.AssistedPerson;
import org.universAAL.ontology.profile.ProfileOntology;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.profile.UserProfile;
import org.universAAL.ontology.profile.service.ProfilingService;
import org.universAAL.ontology.security.AccessRight;
import org.universAAL.ontology.security.AuthorizationService;
import org.universAAL.ontology.security.DelegationForm;
import org.universAAL.ontology.security.Role;
import org.universAAL.ontology.security.RoleManagementService;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.security.SecuritySubprofile;
import org.universAAL.ontology.shape.ShapeOntology;
import org.universAAL.ontology.space.SpaceOntology;
import org.universAAL.ontology.vcard.VCardOntology;


/**
 * @author amedrano
 *
 */
public class ServiceCallsIT extends BusTestCase {
	
	private static final String NAMESPACE = "http://tests.universAAL.org/Anonymization#";
	
	private static final String MY_OUTPUT = NAMESPACE +  "ServiceOutput";

	private DefaultServiceCaller scaller;

	private ProjectActivator scallee;

	/**{@inheritDoc} */
	@Override
	protected void setUp() throws Exception {
		super.setUp();
//		OntologyManagement.getInstance().register(mc, new DataRepOntology());
//		OntologyManagement.getInstance().register(mc, new ServiceBusOntology());
//    	OntologyManagement.getInstance().register(mc, new UIBusOntology());
        OntologyManagement.getInstance().register(mc, new LocationOntology());
//		OntologyManagement.getInstance().register(mc, new SysinfoOntology());
        OntologyManagement.getInstance().register(mc, new ShapeOntology());
        OntologyManagement.getInstance().register(mc, new PhThingOntology());
        OntologyManagement.getInstance().register(mc, new SpaceOntology());
        OntologyManagement.getInstance().register(mc, new VCardOntology());
    	OntologyManagement.getInstance().register(mc, new ProfileOntology());
//		OntologyManagement.getInstance().register(mc, new MenuProfileOntology());
		OntologyManagement.getInstance().register(mc, new CryptographicOntology());	
		OntologyManagement.getInstance().register(mc, new SecurityOntology());
		
		
		scallee = new ProjectActivator();
		scallee.start(mc);
		
	}
	
	public void testExecution(){
		scaller = new DefaultServiceCaller(mc);
		
		User u1 = new AssistedPerson(NAMESPACE+"user1");
		SecuritySubprofile sspu1  = new SecuritySubprofile(NAMESPACE + "u1SSP");

    	Role newRole = new Role();

		//add role to SubProfile
		ServiceRequest sreq = new ServiceRequest(new ProfilingService(),u1);
    	sreq.addValueFilter(new String[] {ProfilingService.PROP_CONTROLS,User.PROP_HAS_PROFILE,UserProfile.PROP_HAS_SUB_PROFILE}, sspu1);
    	sreq.addAddEffect(new String[] {ProfilingService.PROP_CONTROLS,User.PROP_HAS_PROFILE,UserProfile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_ROLES}, newRole);
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}

		//remove role from SubProfile
    	sreq = new ServiceRequest(new ProfilingService(),u1);
    	sreq.addValueFilter(new String[] {ProfilingService.PROP_CONTROLS,User.PROP_HAS_PROFILE,UserProfile.PROP_HAS_SUB_PROFILE}, sspu1);
    	sreq.addRemoveEffect(new String[] {ProfilingService.PROP_CONTROLS,User.PROP_HAS_PROFILE,UserProfile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_ROLES});
    	sreq.getRequestedService().addInstanceLevelRestriction(MergedRestriction.getFixedValueRestriction(SecuritySubprofile.PROP_ROLES, newRole), 
    			new String[] {ProfilingService.PROP_CONTROLS,User.PROP_HAS_PROFILE,UserProfile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_ROLES});
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}
    	
    	//add role as subrole
    	sreq = new ServiceRequest(new RoleManagementService(),u1);
    	sreq.addValueFilter(new String[]{RoleManagementService.PROP_ROLE}, newRole);
    	sreq.addAddEffect(new String[]{RoleManagementService.PROP_ROLE,Role.PROP_SUB_ROLES}, new Role());
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}

		//remove role as subrole
    	sreq = new ServiceRequest(new RoleManagementService(),u1);
    	sreq.addValueFilter(new String[]{RoleManagementService.PROP_ROLE}, newRole);
    	sreq.addRemoveEffect(new String[]{RoleManagementService.PROP_ROLE,Role.PROP_SUB_ROLES});
    	sreq.getRequestedService().addInstanceLevelRestriction(MergedRestriction.getFixedValueRestriction(Role.PROP_SUB_ROLES, new Role()), 
    			new String[]{RoleManagementService.PROP_ROLE,Role.PROP_SUB_ROLES});
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}
    	
		//change Role
    	sreq = new ServiceRequest(new RoleManagementService(),u1);
    	sreq.addChangeEffect(new String[]{RoleManagementService.PROP_ROLE}, newRole);
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}

		//get all Roles
    	sreq = new ServiceRequest(new RoleManagementService(),u1);
    	sreq.addRequiredOutput(MY_OUTPUT, new String[]{RoleManagementService.PROP_ROLE});
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}
    	

		//add AccessRight to role
    	sreq = new ServiceRequest(new RoleManagementService(),u1);
    	sreq.addValueFilter(new String[]{RoleManagementService.PROP_ROLE}, newRole);
    	sreq.addAddEffect(new String[]{RoleManagementService.PROP_ROLE,Role.PROP_HAS_ACCESS_RIGHTS}, new AccessRight());
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}

		//remove AccessRight from role
    	sreq = new ServiceRequest(new RoleManagementService(),u1);
    	sreq.addValueFilter(new String[]{RoleManagementService.PROP_ROLE}, newRole);
    	sreq.addRemoveEffect(new String[]{RoleManagementService.PROP_ROLE,Role.PROP_HAS_ACCESS_RIGHTS});
    	sreq.getRequestedService().addInstanceLevelRestriction(MergedRestriction.getFixedValueRestriction(Role.PROP_HAS_ACCESS_RIGHTS, new AccessRight()), 
    			new String[]{RoleManagementService.PROP_ROLE,Role.PROP_HAS_ACCESS_RIGHTS});
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}

		//change AccessRight
    	sreq = new ServiceRequest(new RoleManagementService(),u1);
    	sreq.addChangeEffect(new String[]{RoleManagementService.PROP_ROLE,Role.PROP_HAS_ACCESS_RIGHTS}, new AccessRight());
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}

		//get all Access Rights
    	sreq = new ServiceRequest(new RoleManagementService(),u1);
    	sreq.addRequiredOutput(MY_OUTPUT, new String[]{RoleManagementService.PROP_ROLE,Role.PROP_HAS_ACCESS_RIGHTS});
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}
    	

		//Check READ Access to asset by Challenger User
		sreq = new ServiceRequest(new AuthorizationService(),u1);
    	sreq.addValueFilter(new String[] {AuthorizationService.PROP_CHALLENGER_USER}, u1);
    	sreq.addValueFilter(new String[] {AuthorizationService.PROP_ASSET_ACCESS}, new DelegationForm());
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}
    	
		//Check CHANGE Access to asset by Challenger User
		sreq = new ServiceRequest(new AuthorizationService(),u1);
    	sreq.addValueFilter(new String[] {AuthorizationService.PROP_CHALLENGER_USER}, u1);
    	sreq.addChangeEffect(new String[] {AuthorizationService.PROP_ASSET_ACCESS}, new DelegationForm());
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}
    	
		//Check ADD Access to asset by Challenger User
		sreq = new ServiceRequest(new AuthorizationService(),u1);
    	sreq.addValueFilter(new String[] {AuthorizationService.PROP_CHALLENGER_USER}, u1);
    	sreq.addAddEffect(new String[] {AuthorizationService.PROP_ASSET_ACCESS}, new DelegationForm());
    	
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}
    	
		//Check REMOVE Access to asset by Challenger User
		sreq = new ServiceRequest(new AuthorizationService(),u1);
    	sreq.addValueFilter(new String[] {AuthorizationService.PROP_CHALLENGER_USER}, u1);
    	sreq.addRemoveEffect(new String[] {AuthorizationService.PROP_ASSET_ACCESS});
    	sreq.getRequestedService().addInstanceLevelRestriction(MergedRestriction.getFixedValueRestriction(AuthorizationService.PROP_ASSET_ACCESS, new DelegationForm()), new String[] {AuthorizationService.PROP_ASSET_ACCESS});
    	try {
			ServiceResponse srep = scaller.call(sreq);
			System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}
	}
	
}

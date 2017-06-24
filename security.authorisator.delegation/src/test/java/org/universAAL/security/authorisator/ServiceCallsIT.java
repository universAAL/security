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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import org.universAAL.middleware.bus.junit.BusTestCase;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.serialization.turtle.TurtleSerializer;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.ontology.cryptographic.CryptographicOntology;
import org.universAAL.ontology.cryptographic.asymmetric.RSA;
import org.universAAL.ontology.location.LocationOntology;
import org.universAAL.ontology.phThing.PhThingOntology;
import org.universAAL.ontology.profile.AssistedPerson;
import org.universAAL.ontology.profile.Profilable;
import org.universAAL.ontology.profile.Profile;
import org.universAAL.ontology.profile.ProfileOntology;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.profile.service.ProfilingService;
import org.universAAL.ontology.security.DelegationForm;
import org.universAAL.ontology.security.Role;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.security.SecuritySubprofile;
import org.universAAL.ontology.shape.ShapeOntology;
import org.universAAL.ontology.space.SpaceOntology;
import org.universAAL.ontology.vcard.VCardOntology;
import org.universAAL.security.authorisator.delegation.DelegationActivator;

/**
 * @author amedrano
 *
 */
public class ServiceCallsIT extends BusTestCase {

	private static final String NAMESPACE = "http://tests.universAAL.org/Anonymization#";

	private static final String MY_OUTPUT = NAMESPACE + "ServiceOutput";

	private DefaultServiceCaller scaller;

	private DelegationActivator scallee;

	/** {@inheritDoc} */
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		// OntologyManagement.getInstance().register(mc, new DataRepOntology());
		// OntologyManagement.getInstance().register(mc, new
		// ServiceBusOntology());
		// OntologyManagement.getInstance().register(mc, new UIBusOntology());
		OntologyManagement.getInstance().register(mc, new LocationOntology());
		// OntologyManagement.getInstance().register(mc, new SysinfoOntology());
		OntologyManagement.getInstance().register(mc, new ShapeOntology());
		OntologyManagement.getInstance().register(mc, new PhThingOntology());
		OntologyManagement.getInstance().register(mc, new SpaceOntology());
		OntologyManagement.getInstance().register(mc, new VCardOntology());
		OntologyManagement.getInstance().register(mc, new ProfileOntology());
		// OntologyManagement.getInstance().register(mc, new
		// MenuProfileOntology());
		OntologyManagement.getInstance().register(mc, new CryptographicOntology());
		OntologyManagement.getInstance().register(mc, new SecurityOntology());

		scallee = new DelegationActivator();
		scallee.start(mc);

	}

	public void testExecution() {
		scaller = new DefaultServiceCaller(mc);

		User u1 = new AssistedPerson(NAMESPACE + "user1");
		// SecuritySubprofile sspu1 = new SecuritySubprofile(NAMESPACE +
		// "u1SSP");

		User u2 = new AssistedPerson(NAMESPACE + "user2");
		// SecuritySubprofile sspu2 = new SecuritySubprofile(NAMESPACE +
		// "u2SSP");

		Role role = new Role();

		RSA ae = new RSA();

		// create Delegation Form
		ServiceRequest sreq = new ServiceRequest(new ProfilingService(), u1);
		sreq.addValueFilter(new String[] { ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE,
				Profile.PROP_HAS_SUB_PROFILE, SecuritySubprofile.PROP_DELEGATED_FORMS, DelegationForm.PROP_AUTHORISER },
				u1);
		sreq.addValueFilter(new String[] { ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE,
				Profile.PROP_HAS_SUB_PROFILE, SecuritySubprofile.PROP_DELEGATED_FORMS, DelegationForm.PROP_DELEGATE },
				u2);
		sreq.addValueFilter(new String[] { ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE,
				Profile.PROP_HAS_SUB_PROFILE, SecuritySubprofile.PROP_DELEGATED_FORMS,
				DelegationForm.PROP_DELEGATED_COMPETENCES }, role);
		sreq.addValueFilter(new String[] { ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE,
				Profile.PROP_HAS_SUB_PROFILE, SecuritySubprofile.PROP_DELEGATED_FORMS, DelegationForm.PROP_ASYMMETRIC },
				ae);
		sreq.addRequiredOutput(MY_OUTPUT, new String[] { ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE,
				Profile.PROP_HAS_SUB_PROFILE, SecuritySubprofile.PROP_DELEGATED_FORMS });

		try {
			writeR("./target/Delegation/Request", "Create Delegation From", sreq);
			ServiceResponse srep = scaller.call(sreq);
			// System.out.println(srep.getCallStatus());
			writeR("Delegation/Response", "Create Delegation From", srep);
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}

		// add Delegation form to Delegated User's securitysubprofile
		sreq = new ServiceRequest(new ProfilingService(), u1);
		sreq.addAddEffect(new String[] { ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE,
				Profile.PROP_HAS_SUB_PROFILE, SecuritySubprofile.PROP_DELEGATED_FORMS }, new DelegationForm());

		try {
			writeR("Delegation/Request", "Add Delegation From", sreq);
			ServiceResponse srep = scaller.call(sreq);
			writeR("Delegation/Response", "Add Delegation From", srep);
			// System.out.println(srep.getCallStatus());
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}

		// Delegation form revokation
		sreq = new ServiceRequest(new ProfilingService(), u1);
		sreq.addRemoveEffect(new String[] { ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE,
				Profile.PROP_HAS_SUB_PROFILE, SecuritySubprofile.PROP_DELEGATED_FORMS });
		sreq.getRequestedService().addInstanceLevelRestriction(
				MergedRestriction.getFixedValueRestriction(SecuritySubprofile.PROP_DELEGATED_FORMS,
						new DelegationForm()),
				new String[] { ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE,
						Profile.PROP_HAS_SUB_PROFILE, SecuritySubprofile.PROP_DELEGATED_FORMS });

		try {
			writeR("Delegation/Request", "Add Delegation From", sreq);
			ServiceResponse srep = scaller.call(sreq);
			// System.out.println(srep.getCallStatus());
			writeR(".Delegation/Response", "Add Delegation From", srep);
		} catch (Exception e) {
			// it will fail... this is just to test the call matchmaking
		}
	}

	private void writeR(String folder, String sname, Resource sreq) {
		File dir = new File("./target/" + folder);
		dir.mkdirs();
		File out = new File(dir, sname);
		if (out.exists()) {
			out.delete();
		}
		TurtleSerializer s = new TurtleSerializer();
		String ser = s.serialize(sreq);
		BufferedWriter w = null;
		try {
			w = new BufferedWriter(new FileWriter(out));
			w.write(ser);
			w.flush();

		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		} finally {
			try {
				w.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

}

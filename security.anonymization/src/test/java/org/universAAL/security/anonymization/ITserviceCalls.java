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
package org.universAAL.security.anonymization;

import org.universAAL.container.JUnit.JUnitModuleContext;
import org.universAAL.middleware.bus.junit.BusTestCase;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.CryptographicOntology;
import org.universAAL.ontology.cryptographic.EncryptionService;
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.cryptographic.asymmetric.RSA;
import org.universAAL.ontology.location.LocationOntology;
import org.universAAL.ontology.phThing.PhThingOntology;
import org.universAAL.ontology.profile.ProfileOntology;
import org.universAAL.ontology.profile.UserProfile;
import org.universAAL.ontology.security.Anonymizable;
import org.universAAL.ontology.security.AnonymizationService;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.shape.ShapeOntology;
import org.universAAL.ontology.space.SpaceOntology;
import org.universAAL.ontology.vcard.VCardOntology;


/**
 * @author amedrano
 *
 */
public class ITserviceCalls extends BusTestCase {
	
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
		
		//register Encryption services module...
		new org.universAAL.security.cryptographic.services
			.ProjectActivator().start(new JUnitModuleContext());
		
		scallee = new ProjectActivator();
		scallee.start(mc);
		
	}
	
	public void testExecution(){
		scaller = new DefaultServiceCaller(mc);
		
		Resource r = RandomResourceGenerator.randomResource();
		
		UserProfile a = new UserProfile(NAMESPACE+"testUP");
		assertTrue(a.changeProperty(Anonymizable.PROP_ANNONYMOUS_RESOURCE, r));
		
		AsymmetricEncryption ae = new RSA();
		ae.addKeyRing(keyringKeygen(ae, 1024));
		
		System.out.println(serialize(AnonServiceProfile.profs[0]));
		
		ServiceRequest sreq = new ServiceRequest(new AnonymizationService(), null);
		
		sreq.addValueFilter(new String[]{AnonymizationService.PROP_ASYMMETRIC_ENCRYPTION}, ae);
		sreq.addValueFilter(new String[]{AnonymizationService.PROP_ANONYMIZABLE}, a);
		sreq.addChangeEffect(new String[]{AnonymizationService.PROP_ANONYMIZABLE,Anonymizable.PROP_ANNONYMOUS_RESOURCE}, r);
		sreq.addRequiredOutput(MY_OUTPUT, new String[]{AnonymizationService.PROP_ANONYMIZABLE});
		
		System.out.println(serialize(sreq));
		ServiceResponse sres = scaller.call(sreq);
		assertEquals(CallStatus.succeeded, sres.getCallStatus());
	}

	private KeyRing keyringKeygen(AsymmetricEncryption ae, int keylength) {
		ServiceRequest sreq = new ServiceRequest(new EncryptionService(), null);
		
		sreq.addValueFilter(new String [] {EncryptionService.PROP_ENCRYPTION}, ae );
		sreq.addValueFilter(new String[]{EncryptionService.PROP_ENCRYPTION,RSA.PROP_KEY_RING,KeyRing.PROP_KEY_LENGTH}, Integer.valueOf(keylength) );
		//if previous statement is left out, even the propfile having cardinality 0,1 it will not match.
		sreq.addRequiredOutput(MY_OUTPUT, new String[]{EncryptionService.PROP_ENCRYPTION,RSA.PROP_KEY_RING});
		
		ServiceResponse sres = scaller.call(sreq);
		assertEquals(CallStatus.succeeded, sres.getCallStatus());
		return (KeyRing) sres.getOutput(MY_OUTPUT).get(0);
		
	}
	
}

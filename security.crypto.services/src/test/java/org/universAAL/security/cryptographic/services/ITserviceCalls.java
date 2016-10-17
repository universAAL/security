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
package org.universAAL.security.cryptographic.services;

import org.universAAL.middleware.bus.junit.BusTestCase;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.service.AggregatingFilter;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.ontology.cryptographic.CryptographicOntology;
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.cryptographic.DigestService;
import org.universAAL.ontology.cryptographic.EncryptionService;
import org.universAAL.ontology.cryptographic.SimpleKey;
import org.universAAL.ontology.cryptographic.SymmetricEncryption;
import org.universAAL.ontology.cryptographic.asymmetric.RSA;
import org.universAAL.ontology.cryptographic.digest.MessageDigest;
import org.universAAL.ontology.cryptographic.digest.SecureHashAlgorithm;
import org.universAAL.ontology.cryptographic.symmetric.AES;
import org.universAAL.ontology.cryptographic.symmetric.Blowfish;
import org.universAAL.ontology.cryptographic.symmetric.DES;


/**
 * @author amedrano
 *
 */
public class ITserviceCalls extends BusTestCase {
	
	private static final String NAMESPACE = "http://tests.universAAL.org/CryptoServices#";
	
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
//        OntologyManagement.getInstance().register(mc, new LocationOntology());
//		OntologyManagement.getInstance().register(mc, new SysinfoOntology());
//        OntologyManagement.getInstance().register(mc, new ShapeOntology());
//        OntologyManagement.getInstance().register(mc, new PhThingOntology());
//        OntologyManagement.getInstance().register(mc, new SpaceOntology());
//        OntologyManagement.getInstance().register(mc, new VCardOntology());
//    	OntologyManagement.getInstance().register(mc, new ProfileOntology());
//		OntologyManagement.getInstance().register(mc, new MenuProfileOntology());
		OntologyManagement.getInstance().register(mc, new CryptographicOntology());
		
		scallee = new ProjectActivator();
		scallee.start(mc);
		
	}
	
	public void testExecution(){
		scaller = new DefaultServiceCaller(mc);
		
		//Digest tests
		callWDigest(MessageDigest.IND_MD2);
//		callWDigest(MessageDigest.IND_MD5);
//		callWDigest(SecureHashAlgorithm.IND_SHA);
//		callWDigest(SecureHashAlgorithm.IND_SHA256);
//		callWDigest(SecureHashAlgorithm.IND_SHA384);
//		callWDigest(SecureHashAlgorithm.IND_SHA512);
		
		//Key Generation
		simpleKeygen(new AES(),128);
		simpleKeygen(new Blowfish(),128);
		simpleKeygen(new DES(),56); 
	}

	private void callWDigest(Digest method) {
		Resource example = RandomResourceGenerator.randomResource();
		
		ServiceRequest sreq = new ServiceRequest(new DigestService(), null);
		sreq.addRequiredOutput(MY_OUTPUT, new String[] {DigestService.PROP_DIGESTED_TEXT});
		sreq.addValueFilter(new String [] {DigestService.PROP_RESOURCE_TO_DIGEST}, example);
		sreq.addValueFilter(new String[] {DigestService.PROP_DIGEST_METHOD}, method);
		
		ServiceResponse sres = scaller.call(sreq);
		assertEquals(CallStatus.succeeded, sres.getCallStatus());
	}
	private SimpleKey simpleKeygen(SymmetricEncryption se, int keylength){
		ServiceRequest sreq = new ServiceRequest(new EncryptionService(), null);
		
		sreq.addValueFilter(new String [] {EncryptionService.PROP_ENCRYPTION}, se );
		sreq.addValueFilter(new String[]{EncryptionService.PROP_ENCRYPTION,SymmetricEncryption.PROP_SIMPLE_KEY,SimpleKey.PROP_KEY_LENGTH}, Integer.valueOf(keylength) );
		//if previous statement is left out, even the propfile having cardinality 0,1 it will not match.
		sreq.addRequiredOutput(MY_OUTPUT, new String[]{EncryptionService.PROP_ENCRYPTION,SymmetricEncryption.PROP_SIMPLE_KEY});
		
		ServiceResponse sres = scaller.call(sreq);
		assertEquals(CallStatus.succeeded, sres.getCallStatus());
		return (SimpleKey) sres.getOutput(MY_OUTPUT).get(0);
	}

}

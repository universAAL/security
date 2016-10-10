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

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.serialization.turtle.TurtleSerializer;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.cryptographic.MultidestinationEncryptedResource;
import org.universAAL.ontology.cryptographic.asymmetric.RSA;

/**
 * @author amedrano
 *
 */
public class MDERTest extends CommonTest {

	public void test() throws Exception{
		RSA rsa = new RSA();
		KeyRing ku1 = EncryptionServiceCallee.generateKeyRing(rsa, null);
		KeyRing ku2 = EncryptionServiceCallee.generateKeyRing(rsa, null);
		KeyRing ku3 = EncryptionServiceCallee.generateKeyRing(rsa, null);
		
		RSA enc1 = new RSA();
		enc1.addKeyRing(ku1);
		RSA enc2 = new RSA();
		enc2.addKeyRing(ku2);
//		RSA enc3 = new RSA();
//		enc1.addKey(ku3);
		
		Resource r = RandomResourceGenerator.randomResource();
		
		List<AsymmetricEncryption> ael = new ArrayList<AsymmetricEncryption>();
		
		MultidestinationEncryptedResource mder = MultiDestinationServiceImpl.createMDER(r, null, ael);
		
		ael.add(enc1);
		ael.add(enc2);
		
		mder = MultiDestinationServiceImpl.createMDER(r, null, ael);
		
		System.out.println(new TurtleSerializer().serialize(mder));
		
		Resource r2 = MultiDestinationServiceImpl.decrypt(mder, ku1);
		assertEquals(r, r2);
		assertTrue(EncryptTest.fullResourceEquals(r, r2));
		
		r2 = MultiDestinationServiceImpl.decrypt(mder, ku2);
		assertEquals(r, r2);
		assertTrue(EncryptTest.fullResourceEquals(r, r2));
		
		r2 = MultiDestinationServiceImpl.decrypt(mder, ku3);
		assertNull(r2);
		
//		ael.clear();
//		ael.add(enc3); //XXX: test what happens if add an existing destination.
//		
//		mder = MultiDestinationServiceImpl.addToMDERDest(mder, ku1, ael);
		
	}

}

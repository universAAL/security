/*******************************************************************************
 * Copyright 2016 2011 Universidad Politécnica de Madrid
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

import org.universAAL.middleware.rdf.Resource;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.cryptographic.SignedResource;
import org.universAAL.ontology.cryptographic.asymmetric.RSA;
import org.universAAL.ontology.cryptographic.digest.MessageDigest;

/**
 * @author amedrano
 * 
 */
public class SignTest extends CommonTest {

//	public void test() throws Exception{
//		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//		keyGen.initialize(512);
//		System.out.println( keyGen.genKeyPair().getPublic().getFormat());
//		System.out.println(keyGen.genKeyPair().getPrivate().getFormat());
//	}
	
	public void testSign() throws Exception{
		AsymmetricEncryption enc = new RSA();
		Digest dig = MessageDigest.IND_MD5;
		KeyRing kr = EncryptionServiceCallee.generateKeyRing(enc, null);
		
		Resource r = RandomResourceGenerator.randomResource();
		
		SignedResource sr = SignVerifyCallee.sign(r, dig, enc, kr.getPrivateKey());
		
		assertEquals(r, sr.getSignedResource());
		
		Boolean verify = SignVerifyCallee.verify(sr, dig, enc, kr.getPublicKey());
		assertEquals(Boolean.TRUE, verify);
		
		verify = SignVerifyCallee.verify(sr, dig, enc, EncryptionServiceCallee.generateKeyRing(enc, null).getPublicKey());
		assertEquals(Boolean.FALSE, verify);
	}
}

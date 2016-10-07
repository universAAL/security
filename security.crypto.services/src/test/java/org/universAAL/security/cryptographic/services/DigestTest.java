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
import org.universAAL.middleware.xsd.Base64Binary;
import org.universAAL.ontology.cryptographic.digest.MessageDigest;
import org.universAAL.ontology.cryptographic.digest.SecureHashAlgorithm;

/**
 * @author amedrano
 *
 */
public class DigestTest extends CommonTest {
	

	public void testMD2() throws Exception{
		
		Resource r = RandomResourceGenerator.randomResource();
		
		Base64Binary hash = DigestServiceCallee.digestResource(r, MessageDigest.IND_MD2);
		
		assertNotNull(hash);
		assertNotSame(hash, DigestServiceCallee.digestResource(RandomResourceGenerator.randomResource(), MessageDigest.IND_MD2));
		assertNotSame(hash, DigestServiceCallee.digestResource(r, MessageDigest.IND_MD5));
	}
	
	public void testMD5() throws Exception{
		
		Resource r = RandomResourceGenerator.randomResource();
		
		Base64Binary hash = DigestServiceCallee.digestResource(r, MessageDigest.IND_MD5);
		
		assertNotNull(hash);
		assertNotSame(hash, DigestServiceCallee.digestResource(RandomResourceGenerator.randomResource(), MessageDigest.IND_MD5));
		assertEquals(hash, DigestServiceCallee.digestResource(r, MessageDigest.IND_MD5));
	}
	
public void testSHA() throws Exception{
		
		Resource r = RandomResourceGenerator.randomResource();
		
		Base64Binary hash = DigestServiceCallee.digestResource(r, SecureHashAlgorithm.IND_SHA);
		assertNotNull(hash);
		assertNotSame(hash, DigestServiceCallee.digestResource(RandomResourceGenerator.randomResource(), SecureHashAlgorithm.IND_SHA256));
		assertNotSame(hash, DigestServiceCallee.digestResource(RandomResourceGenerator.randomResource(), SecureHashAlgorithm.IND_SHA384));
		assertNotSame(hash, DigestServiceCallee.digestResource(RandomResourceGenerator.randomResource(), SecureHashAlgorithm.IND_SHA512));
		assertEquals(hash, DigestServiceCallee.digestResource(r, SecureHashAlgorithm.IND_SHA));
	}
	
}

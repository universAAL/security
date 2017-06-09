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

import java.security.InvalidKeyException;
import java.util.Collections;
import java.util.HashSet;

import javax.crypto.BadPaddingException;

import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.xsd.Base64Binary;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.EncryptedResource;
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.cryptographic.SimpleKey;
import org.universAAL.ontology.cryptographic.SymmetricEncryption;
import org.universAAL.ontology.cryptographic.asymmetric.RSA;
import org.universAAL.ontology.cryptographic.symmetric.AES;
import org.universAAL.ontology.cryptographic.symmetric.Blowfish;
import org.universAAL.ontology.cryptographic.symmetric.DES;

/**
 * @author amedrano
 */
public class EncryptTest extends CommonTest {

	/**
	 * @param testR
	 * @param detestR
	 * @return
	 */
	static boolean fullResourceEquals(Resource a, Resource b) {
		HashSet aSet = new HashSet(Collections.list(a.getPropertyURIs()));
		HashSet bSet = new HashSet(Collections.list(b.getPropertyURIs()));
		if (!aSet.equals(bSet)) {
			return false;
		}
		for (Object prop : aSet) {
			Object val = a.getProperty((String) prop);
			if (val instanceof Resource
					&& !fullResourceEquals((Resource) val, (Resource) b.getProperty((String) prop))) {
				return false;
			} else if (!val.equals(b.getProperty((String) prop))) {
				return false;
			}
		}

		return true;
	}

	public void testAES() throws Exception {
		SymmetricEncryption aes = new AES();
		SimpleKey key = EncryptionServiceCallee.generateSymmetricKey(aes, null);
		aes.addKey(key);
		Resource testR = RandomResourceGenerator.randomResource();

		EncryptedResource enc = EncryptionServiceCallee.doEncryption(testR, key.getKeyText(), aes);

		assertEquals(0, enc.getEncryption().getKey().length);
		assertNull(((SymmetricEncryption) enc.getEncryption()).getSimpleKey());

		Resource detestR = EncryptionServiceCallee.doDecryption(enc, key.getKeyText(), aes);

		assertNotNull(detestR);
		assertTrue(fullResourceEquals(testR, detestR));

		Resource detestR2;
		try {
			detestR2 = EncryptionServiceCallee.doDecryption(enc,
					EncryptionServiceCallee.generateSymmetricKey(new AES(), null).getKeyText(), new AES());
		} catch (BadPaddingException e) {
			assertTrue(true);
		} catch (Exception e) {
			assertTrue(false);
		}

		try {
			detestR2 = EncryptionServiceCallee.doDecryption(enc, key.getKeyText(), new DES());
		} catch (InvalidKeyException e) {
			assertTrue(true);
		} catch (Exception e) {
			assertTrue(false);
		}

	}

	public void testBlofish() throws Exception {
		SymmetricEncryption blo = new Blowfish();
		SimpleKey key = EncryptionServiceCallee.generateSymmetricKey(blo, null);
		blo.addKey(key);
		Resource testR = RandomResourceGenerator.randomResource();

		EncryptedResource enc = EncryptionServiceCallee.doEncryption(testR, key.getKeyText(), blo);

		assertEquals(0, enc.getEncryption().getKey().length);
		assertNull(((SymmetricEncryption) enc.getEncryption()).getSimpleKey());

		Resource detestR = EncryptionServiceCallee.doDecryption(enc, key.getKeyText(), blo);

		assertNotNull(detestR);
		assertTrue(fullResourceEquals(testR, detestR));

		Resource detestR2;
		try {
			detestR2 = EncryptionServiceCallee.doDecryption(enc,
					EncryptionServiceCallee.generateSymmetricKey(new Blowfish(), null).getKeyText(), new Blowfish());
		} catch (BadPaddingException e) {
			assertTrue(true);
		} catch (Exception e) {
			assertTrue(false);
		}

		try {
			detestR2 = EncryptionServiceCallee.doDecryption(enc, key.getKeyText(), new DES());
		} catch (InvalidKeyException e) {
			assertTrue(true);
		} catch (Exception e) {
			assertTrue(false);
		}

	}

	public void testDES() throws Exception {
		SymmetricEncryption des = new DES();
		SimpleKey key = EncryptionServiceCallee.generateSymmetricKey(des, null);
		des.addKey(key);
		Resource testR = RandomResourceGenerator.randomResource();

		EncryptedResource enc = EncryptionServiceCallee.doEncryption(testR, key.getKeyText(), des);

		assertEquals(0, enc.getEncryption().getKey().length);
		assertNull(((SymmetricEncryption) enc.getEncryption()).getSimpleKey());

		Resource detestR = EncryptionServiceCallee.doDecryption(enc, key.getKeyText(), des);

		assertNotNull(detestR);
		assertTrue(fullResourceEquals(testR, detestR));

		Resource detestR2;
		try {
			detestR2 = EncryptionServiceCallee.doDecryption(enc,
					EncryptionServiceCallee.generateSymmetricKey(new DES(), null).getKeyText(), new DES());
		} catch (BadPaddingException e) {
			assertTrue(true);
		} catch (Exception e) {
			assertTrue(false);
		}

		try {
			detestR2 = EncryptionServiceCallee.doDecryption(enc, key.getKeyText(), new AES());
		} catch (InvalidKeyException e) {
			assertTrue(true);
		} catch (Exception e) {
			assertTrue(false);
		}

	}

	public void testRSA() throws Exception {
		AsymmetricEncryption rsa = new RSA();
		KeyRing kr = EncryptionServiceCallee.generateKeyRing(new RSA(), 1024); // FIXME
																				// only
																				// 1024
																				// byte
																				// keys
																				// supported!!!
		rsa.addKeyRing(kr);

		Resource testR = RandomResourceGenerator.randomResource();

		EncryptedResource enc = EncryptionServiceCallee.doEncryption(testR, kr.getPublicKey(), rsa);

		assertEquals(0, enc.getEncryption().getKey().length);

		// System.out.println(Arrays.toString(enc.getCypheredText().getVal()));
		Resource detestR = EncryptionServiceCallee.doDecryption(enc, kr.getPrivateKey(), rsa);

		assertNotNull(detestR);
		assertTrue(fullResourceEquals(testR, detestR));

	}

}

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

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.serialization.turtle.TurtleSerializer;
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.cryptographic.asymmetric.RSA;
import org.universAAL.security.cryptographic.services.utils.BlockChipher;

/**
 * @author amedrano
 *
 */
public class BlockTest extends CommonTest {

	public void test() throws Exception {

		// KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		// kpg.initialize(1024);
		// KeyPair keypair = kpg.generateKeyPair();
		// byte[] codedPuK = keypair.getPublic().getEncoded();
		// byte[] codedPrK = keypair.getPrivate().getEncoded();

		KeyRing kr = EncryptionServiceCallee.generateKeyRing(new RSA(), 1024);

		// Base64Binary b64Puk = new Base64Binary(codedPuK);

		PublicKey publicKey = KeyFactory.getInstance("RSA")
				.generatePublic(new X509EncodedKeySpec(kr.getPublicKey().getVal()));
		PrivateKey privateKey = KeyFactory.getInstance("RSA")
				.generatePrivate(new PKCS8EncodedKeySpec(kr.getPrivateKey().getVal()));

		Cipher c = Cipher.getInstance("RSA");
		BlockChipher bc = new BlockChipher(c);

		Resource testR = RandomResourceGenerator.randomResource();
		TurtleSerializer ts = new TurtleSerializer();
		String s = ts.serialize(testR);
		// System.out.println(s);

		byte[] enc = bc.encrypt(s, publicKey);

		String s2 = bc.decrypt(enc, privateKey);

		assertEquals(s, s2);

	}

}

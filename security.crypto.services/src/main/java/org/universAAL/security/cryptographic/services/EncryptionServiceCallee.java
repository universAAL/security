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

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.owl.ManagedIndividual;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.ServiceCall;
import org.universAAL.middleware.service.ServiceCallee;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.process.ProcessOutput;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.middleware.xsd.Base64Binary;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.EncryptedResource;
import org.universAAL.ontology.cryptographic.Encryption;
import org.universAAL.ontology.cryptographic.EncryptionKey;
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.cryptographic.SimpleKey;
import org.universAAL.ontology.cryptographic.SymmetricEncryption;
import org.universAAL.ontology.cryptographic.asymmetric.RSA;
import org.universAAL.ontology.cryptographic.symmetric.AES;
import org.universAAL.ontology.cryptographic.symmetric.Blowfish;
import org.universAAL.ontology.cryptographic.symmetric.DES;
import org.universAAL.security.cryptographic.services.utils.BlockChipher;

/**
 * @author amedrano
 * 
 */
public class EncryptionServiceCallee extends ServiceCallee {

	/**
	 * @param context
	 * @param realizedServices
	 */
	public EncryptionServiceCallee(ModuleContext context, ServiceProfile[] realizedServices) {
		super(context, realizedServices);
	}

	/**
	 * @param context
	 * @param realizedServices
	 * @param throwOnError
	 */
	public EncryptionServiceCallee(ModuleContext context, ServiceProfile[] realizedServices, boolean throwOnError) {
		super(context, realizedServices, throwOnError);
	}

	/** {@inheritDoc} */
	@Override
	public void communicationChannelBroken() {
	}

	/** {@inheritDoc} */
	@Override
	public ServiceResponse handleCall(ServiceCall call) {
		Base64Binary key = null;
		boolean symmetrical = true;
		Encryption algorithm = (Encryption) call.getInputValue(EncryptionServiceProfiles.METHOD);
		if (call.getProcessURI().contains("generate-new")) {
			try {
				EncryptionKey out;
				if (ManagedIndividual.checkMembership(SymmetricEncryption.MY_URI, algorithm)) {
					out = generateSymmetricKey((SymmetricEncryption) algorithm,
							call.getInputValue(EncryptionServiceProfiles.KEY_LENGTH));
				} else {
					out = generateKeyRing((AsymmetricEncryption) algorithm,
							call.getInputValue(EncryptionServiceProfiles.KEY_LENGTH));
				}
				ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
				sr.addOutput(new ProcessOutput(EncryptionServiceProfiles.KEY, out));
				return sr;
			} catch (Exception e) {
				LogUtils.logError(owner, getClass(), "GenerateRSAkeyring", new String[] { "Something whent wrong" }, e);
				return new ServiceResponse(CallStatus.serviceSpecificFailure);
			}
		}
		if (ManagedIndividual.checkMembership(AsymmetricEncryption.MY_URI, algorithm)) {
			symmetrical = false;
			// if it is an asymmetrical operation resolve the Key to use
			KeyRing keyring = (KeyRing) call.getInputValue(EncryptionServiceProfiles.KEY);
			// key = resolveKey(keyring);
			if (call.getProcessURI().contains("encrypt")) {
				key = keyring.getPublicKey();
			} else if (call.getProcessURI().contains("decrypt")) {
				key = keyring.getPrivateKey();
			}

			if (key == null) {
				ServiceResponse sr = new ServiceResponse(CallStatus.serviceSpecificFailure);
				sr.setResourceComment("MAN! I need at least one key; public or private does not matter!");
				return sr;
			}
		} else {
			SimpleKey sk = (SimpleKey) call.getInputValue(EncryptionServiceProfiles.KEY);
			key = sk.getKeyText();
		}
		if (call.getProcessURI().contains("encrypt")) {
			Resource ir = (Resource) call.getInputValue(EncryptionServiceProfiles.CLEAR_RESOURCE);
			EncryptedResource er = null;

			try {
				if (symmetrical) {
					er = doEncryption(ir, key, (SymmetricEncryption) algorithm);
				} else {
					// encryption with Asymmetrical
					er = doEncryption(ir, key, (AsymmetricEncryption) algorithm);
				}
			} catch (Exception e) {
				LogUtils.logError(owner, getClass(), "Encrypt" + algorithm, new String[] { "unable to encrypt." }, e);
				return new ServiceResponse(CallStatus.serviceSpecificFailure);
			}
			ProcessOutput po = new ProcessOutput(EncryptionServiceProfiles.ENCRYPTED_RESOURCE, er);

			ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
			sr.addOutput(po);

			return sr;
		}
		if (call.getProcessURI().contains("decrypt")) {
			EncryptedResource ir = (EncryptedResource) call.getInputValue(EncryptionServiceProfiles.ENCRYPTED_RESOURCE);
			Encryption method = (Encryption) call.getInputValue(EncryptionServiceProfiles.METHOD);
			if (ir.hasProperty(EncryptedResource.PROP_ENCRYPTION) && !ir.getEncryption().equals(method)) {
				ServiceResponse sr = new ServiceResponse(CallStatus.serviceSpecificFailure);
				sr.setResourceComment("EncryptedResource Method and Solicited method don't match. Aborting");
				return sr;
			}

			Resource r = null;

			try {
				if (symmetrical) {
					r = doDecryption(ir, key, (SymmetricEncryption) algorithm);
				} else {
					// decryption with Asymmetrical
					r = doDecryption(ir, key, (AsymmetricEncryption) algorithm);

				}

			} catch (Exception e) {
				LogUtils.logError(owner, getClass(), "Decrypt" + algorithm, new String[] { "unable to decrypt." }, e);
				return new ServiceResponse(CallStatus.serviceSpecificFailure);
			}

			ProcessOutput po = new ProcessOutput(EncryptionServiceProfiles.CLEAR_RESOURCE, r);
			ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
			sr.addOutput(po);

			return sr;

		}

		return new ServiceResponse(CallStatus.noMatchingServiceFound);
	}

	static EncryptedResource doEncryption(Resource ir, Base64Binary key, SymmetricEncryption algorithm)
			throws GeneralSecurityException {
		String alg = getJavaCipherProviderFromEncryption(algorithm);
		Cipher cipher = Cipher.getInstance(alg);

		// Serialize Resource
		String message = ProjectActivator.serializer.getObject().serialize(ir);

		// configure cipher
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getVal(), alg));
		// Encrypt
		byte[] byteCipherText = cipher.doFinal(message.getBytes());

		// Collect result
		EncryptedResource or = new EncryptedResource();
		Encryption cleanE = (Encryption) algorithm.copy(false);
		cleanE.changeProperty(Encryption.PROP_KEY, null);
		cleanE.changeProperty(SymmetricEncryption.PROP_SIMPLE_KEY, null);
		or.setEncryption(cleanE);
		or.setCypheredText(new Base64Binary(byteCipherText));
		return or;
	}

	static Resource doDecryption(EncryptedResource ir, Base64Binary key, SymmetricEncryption encrytionAlgorithm)
			throws GeneralSecurityException {
		String alg = getJavaCipherProviderFromEncryption(encrytionAlgorithm);
		Cipher cipher = Cipher.getInstance(alg);

		// configure cipher
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getVal(), alg));
		// Encrypt
		byte[] clearText = cipher.doFinal(ir.getCypheredText().getVal());

		// Collect result
		// deserialize Resource
		Resource or = (Resource) ProjectActivator.serializer.getObject()
				.deserialize(new String(clearText, Charset.forName("UTF8")));

		return or;
	}

	static SimpleKey generateSymmetricKey(SymmetricEncryption enc, Object preferredKeyLength)
			throws NoSuchAlgorithmException {
		int keyLength;
		if (preferredKeyLength == null || !(preferredKeyLength instanceof Integer)
				|| ((Integer) preferredKeyLength).intValue() == 0) {
			if (enc.getClassURI().equals(DES.MY_URI)) {
				keyLength = 56;
			} else {
				keyLength = 128;
			}
		} else {
			keyLength = ((Integer) preferredKeyLength).intValue();
		}

		KeyGenerator keyGen = KeyGenerator.getInstance(getJavaCipherProviderFromEncryption(enc));
		keyGen.init(keyLength);

		// generate Keyring
		SimpleKey out = new SimpleKey();
		out.setKeyText(new Base64Binary(keyGen.generateKey().getEncoded()));
		out.setProperty(EncryptionKey.PROP_KEY_LENGTH, new Integer(keyLength));
		return out;
	}

	static EncryptedResource doEncryption(Resource ir, Base64Binary publickey, AsymmetricEncryption algorithm)
			throws Exception {
		String alg = getJavaCipherProviderFromEncryption(algorithm);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publickey.getVal());
		KeyFactory keyFactory = KeyFactory.getInstance(alg);
		PublicKey puKey = keyFactory.generatePublic(keySpec);

		// Serialize Resource
		String message = ProjectActivator.serializer.getObject().serialize(ir);

		BlockChipher bc = new BlockChipher(Cipher.getInstance(alg));
		// Encrypt
		byte[] byteCipherText = bc.encrypt(message, puKey);

		// Collect result
		EncryptedResource or = new EncryptedResource();
		Encryption cleanE = (Encryption) algorithm.copy(false);
		cleanE.changeProperty(Encryption.PROP_KEY, null);
		cleanE.changeProperty(AsymmetricEncryption.PROP_KEY_RING, null);
		or.setEncryption(cleanE);
		or.setCypheredText(new Base64Binary(byteCipherText));
		return or;
	}

	static Resource doDecryption(EncryptedResource ir, Base64Binary privatekey, AsymmetricEncryption algorithm)
			throws Exception {
		String alg = getJavaCipherProviderFromEncryption(algorithm);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privatekey.getVal());
		KeyFactory keyFactory = KeyFactory.getInstance(alg);
		PrivateKey prKey = keyFactory.generatePrivate(keySpec);
		// configure cipher
		BlockChipher bc = new BlockChipher(Cipher.getInstance(alg));
		// Decrypt
		String clearText = bc.decrypt(ir.getCypheredText().getVal(), prKey);

		// Collect result
		// deserialize Resource
		Resource or = (Resource) ProjectActivator.serializer.getObject().deserialize(clearText);

		return or;
	}

	static KeyRing generateKeyRing(AsymmetricEncryption algorithm, Object preferredKeyLength)
			throws NoSuchAlgorithmException {
		int keyLength;
		if (preferredKeyLength == null || !(preferredKeyLength instanceof Integer)
				|| ((Integer) preferredKeyLength).intValue() == 0) {
			keyLength = 1024;
		} else {
			keyLength = ((Integer) preferredKeyLength).intValue();
		}
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(getJavaCipherProviderFromEncryption(algorithm));
		keyGen.initialize(keyLength);
		KeyPair kp = keyGen.generateKeyPair();
		byte[] publicKey = kp.getPublic().getEncoded();
		byte[] privateKey = kp.getPrivate().getEncoded();

		// generate Keyring
		KeyRing out = new KeyRing();
		out.setPublicKey(new Base64Binary(publicKey));
		out.setPrivateKey(new Base64Binary(privateKey));
		out.setProperty(EncryptionKey.PROP_KEY_LENGTH, new Integer(keyLength));
		return out;
	}

	static String getJavaCipherProviderFromEncryption(Encryption enc) {
		if (ManagedIndividual.checkMembership(AES.MY_URI, enc)) {
			return "AES";
		}
		if (ManagedIndividual.checkMembership(Blowfish.MY_URI, enc)) {
			return "Blowfish";
		}
		if (ManagedIndividual.checkMembership(DES.MY_URI, enc)) {
			return "DES";
		}
		if (ManagedIndividual.checkMembership(RSA.MY_URI, enc)) {
			return "RSA";
		}
		return null;
	}
}

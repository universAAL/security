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
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
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

/**
 * @author amedrano
 * 
 */
public class EncryptionServiceCallee extends ServiceCallee {

	/**
	 * @param context
	 * @param realizedServices
	 */
	public EncryptionServiceCallee(ModuleContext context,
			ServiceProfile[] realizedServices) {
		super(context, realizedServices);
	}

	/**
	 * @param context
	 * @param realizedServices
	 * @param throwOnError
	 */
	public EncryptionServiceCallee(ModuleContext context,
			ServiceProfile[] realizedServices, boolean throwOnError) {
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
		Encryption algorithm = (Encryption) call.getInputValue(EncryptionServiceProfiles.METHOD);
		if (call.getProcessURI().contains("generate-new")){
			try {
				EncryptionKey out;
				if (ManagedIndividual.checkMembership(SymmetricEncryption.MY_URI, algorithm)){
					out = generateSymmetricKey((SymmetricEncryption) algorithm,call.getInputValue(EncryptionServiceProfiles.KEY_LENGTH));
				}
				else {
					out = generateKeyRing((AsymmetricEncryption) algorithm, call.getInputValue(EncryptionServiceProfiles.KEY_LENGTH));
				}
				ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
				sr.addOutput(new ProcessOutput(EncryptionServiceProfiles.KEY, out));
				return sr;
			} catch (Exception e) {
				LogUtils.logError(owner, getClass(), "GenerateRSAkeyring", new String []{"Something whent wrong"}, e);
				return new ServiceResponse(CallStatus.serviceSpecificFailure);
			}
		}
		if (ManagedIndividual.checkMembership(AsymmetricEncryption.MY_URI, algorithm)) {
			//if it is an asymmetrical operation resolve the Key to use
			KeyRing keyring = (KeyRing) call
					.getInputValue(EncryptionServiceProfiles.KEY);
			key = resolveKey(keyring);
			if (key == null){
				ServiceResponse sr =  new ServiceResponse(CallStatus.serviceSpecificFailure);
				sr.setResourceComment("MAN! I need at least one key; public or private does not matter!");
				return sr;
			}
		} else {
			key = (Base64Binary) call
					.getInputValue(EncryptionServiceProfiles.KEY);
		}
		if (call.getProcessURI().contains("encrypt")) {
			Resource ir = (Resource) call
					.getInputValue(EncryptionServiceProfiles.CLEAR_RESOURCE);
			try {

				ProcessOutput po = new ProcessOutput(
						EncryptionServiceProfiles.ENCRYPTED_RESOURCE,
						doEncryption(ir, key, algorithm));
				ServiceResponse sr = new ServiceResponse(
						CallStatus.succeeded);
				sr.addOutput(po);

				return sr;

			} catch (Exception e) {
				LogUtils.logError(owner, getClass(), "Encrypt"
						+ algorithm,
						new String[] { "unable to encrypt." }, e);
				return new ServiceResponse(
						CallStatus.serviceSpecificFailure);
			}
		}
		if (call.getProcessURI().contains("decrypt")) {
			EncryptedResource ir = (EncryptedResource) call
					.getInputValue(EncryptionServiceProfiles.ENCRYPTED_RESOURCE);
			Encryption method = (Encryption) call.getInputValue(EncryptionServiceProfiles.METHOD);
			if ( ir.hasProperty(EncryptedResource.PROP_ENCRYPTION) && !ir.getEncryption().equals(method)){
				ServiceResponse sr = new ServiceResponse(CallStatus.serviceSpecificFailure);
				sr.setResourceComment("EncryptedResource Method and Solicited method don't match. Aborting");
				return sr;
			}

			try {

				ProcessOutput po = new ProcessOutput(
						EncryptionServiceProfiles.ENCRYPTED_RESOURCE,
						doDecryption(ir, key, algorithm));
				ServiceResponse sr = new ServiceResponse(
						CallStatus.succeeded);
				sr.addOutput(po);

				return sr;

			} catch (Exception e) {
				LogUtils.logError(owner, getClass(), "Decrypt"
						+ algorithm,
						new String[] { "unable to decrypt." }, e);
				return new ServiceResponse(
						CallStatus.serviceSpecificFailure);
			}

		}

		return new ServiceResponse(CallStatus.noMatchingServiceFound);
	}
	
	static Base64Binary resolveKey(KeyRing keyring) {
		
		Base64Binary key = null;
		
		if (keyring.hasProperty(KeyRing.PROP_PRIVATE_KEY) && !keyring.hasProperty(KeyRing.PROP_PUBLIC_KEY)){
			key = keyring.getPrivateKey();
		}else if (!keyring.hasProperty(KeyRing.PROP_PRIVATE_KEY) && keyring.hasProperty(KeyRing.PROP_PUBLIC_KEY)){
			key = keyring.getPublicKey();
		} else if (keyring.hasProperty(KeyRing.PROP_PRIVATE_KEY) && keyring.hasProperty(KeyRing.PROP_PUBLIC_KEY)){
			key = keyring.getPrivateKey();
		}
		return key;
	}

	static EncryptedResource doEncryption(Resource ir, Base64Binary key,
			Encryption algorithm) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		String alg = getJavaCipherProviderFromEncryption(algorithm);
		Cipher cipher = Cipher.getInstance(alg);

		// Serialize Resource
		String message = ProjectActivator.serializer.getObject().serialize(ir);

		// configure cipher
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getVal(),
				alg));
		// Encrypt
		byte[] byteCipherText = cipher.doFinal(message.getBytes());

		// Collect result
		EncryptedResource or = new EncryptedResource();
		Encryption cleanE = (Encryption) algorithm.copy(false);
		cleanE.changeProperty(Encryption.PROP_KEY, null);
		or.setEncryption(cleanE);
		or.setCypheredText(new Base64Binary(byteCipherText));
		return or;
	}

	static Resource doDecryption(EncryptedResource ir, Base64Binary key,
			Encryption encrytionAlgorithm) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		String alg = getJavaCipherProviderFromEncryption(encrytionAlgorithm);
		Cipher cipher = Cipher.getInstance(alg);

		// configure cipher
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getVal(),
				alg));
		// Encrypt
		byte[] clearText = cipher.doFinal(ir.getCypheredText().getVal());

		// Collect result
		// deserialize Resource
		Resource or = (Resource) ProjectActivator.serializer.getObject()
				.deserialize(new String(clearText, Charset.forName("UTF8")));

		return or;
	}
	
	static SimpleKey generateSymmetricKey(SymmetricEncryption enc, Object preferredKeyLength) throws NoSuchAlgorithmException{
		int keyLength;
		if (preferredKeyLength == null || !(preferredKeyLength instanceof Integer) ||  ((Integer)preferredKeyLength).intValue() == 0){
			if (enc.getClassURI().equals(DES.MY_URI)){
				keyLength = 56;
			}else {
				keyLength = 256;
			}
		} else {
			keyLength = ((Integer)preferredKeyLength).intValue();
		}
		
		KeyGenerator keyGen = KeyGenerator.getInstance(getJavaCipherProviderFromEncryption(enc));
		keyGen.init(keyLength);
						
		//generate Keyring
		SimpleKey out = new SimpleKey();
		out.setKeyText(new Base64Binary(keyGen.generateKey().getEncoded()));
		out.setProperty(EncryptionKey.PROP_KEY_LENGTH, new Integer(keyLength));
		return out;
	}
	
	static KeyRing generateKeyRing (AsymmetricEncryption algorithm, Object preferredKeyLength) throws NoSuchAlgorithmException{
		int keyLength;
		if (preferredKeyLength == null || !(preferredKeyLength instanceof Integer) ||  ((Integer)preferredKeyLength).intValue() == 0){
			keyLength = 512;
		} else {
			keyLength = ((Integer)preferredKeyLength).intValue();
		}
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(getJavaCipherProviderFromEncryption(algorithm));
		keyGen.initialize(keyLength);
		byte[] publicKey = keyGen.genKeyPair().getPublic().getEncoded();
		byte[] privateKey = keyGen.genKeyPair().getPrivate().getEncoded();
		
		//generate Keyring
		KeyRing out = new KeyRing();
		out.setPublicKey(new Base64Binary(publicKey));
		out.setPrivateKey(new Base64Binary(privateKey));
		out.setProperty(EncryptionKey.PROP_KEY_LENGTH, new Integer(keyLength));
		return out;
	}
	
	static String getJavaCipherProviderFromEncryption(Encryption enc){
		if (enc.getURI().equals(AES.MY_URI)){
			return "AES";
		}
		if (enc.getURI().equals(Blowfish.MY_URI)){
			return "Blowfish";
		}
		if (enc.getURI().equals(DES.MY_URI)){
			return "DES";
		}
		if (enc.getURI().equals(RSA.MY_URI)){
			return "RSA";
		}
		return null;
	}
}

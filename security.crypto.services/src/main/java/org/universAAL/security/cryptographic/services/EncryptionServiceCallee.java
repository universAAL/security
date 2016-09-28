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
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.ServiceCall;
import org.universAAL.middleware.service.ServiceCallee;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.process.ProcessOutput;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.middleware.xsd.Base64Binary;
import org.universAAL.ontology.cryptographic.EncryptedResource;

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

	/**{@inheritDoc} */
	@Override
	public void communicationChannelBroken() {
	}

	/**{@inheritDoc} */
	@Override
	public ServiceResponse handleCall(ServiceCall call) {
			
		String[] symAlg = new String[] {"AES","Blowfish","DES"};
			
			for (int i = 0; i < symAlg.length; i++) {
				String algorithm = symAlg[i];
				if (call.getProcessURI().contains(algorithm)) {
					if (call.getProcessURI().contains("encrypt")) {
						Resource ir = (Resource) call
								.getInputValue(EncryptionServiceProfiles.CLEAR_RESOURCE);
						Base64Binary key = (Base64Binary) call
								.getInputValue(EncryptionServiceProfiles.KEY);
						try {

							ProcessOutput po = new ProcessOutput(
									EncryptionServiceProfiles.ENCRYPTED_RESOURCE,
									doSymetricEncryption(ir, key, algorithm));
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
						Base64Binary key = (Base64Binary) call
								.getInputValue(EncryptionServiceProfiles.KEY);

						try {

							ProcessOutput po = new ProcessOutput(
									EncryptionServiceProfiles.ENCRYPTED_RESOURCE,
									doSymetricDecryption(ir, key, algorithm));
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
				}
			}
			
		if (call.getProcessURI().contains(EncryptionServiceProfiles.ENCRYPT_RSA)){
			
		}
		if (call.getProcessURI().contains(EncryptionServiceProfiles.DECRYPT_RSA)){
			
		}
		return new ServiceResponse(CallStatus.noMatchingServiceFound);
	}

	
	private EncryptedResource doSymetricEncryption(Resource ir, Base64Binary key, String encrytionAlgorithm) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(encrytionAlgorithm);

		// Serialize Resource
		String message = ProjectActivator.serializer.getObject().serialize(ir);

		//configure cipher
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getVal(), encrytionAlgorithm) );
		//Encrypt
		byte[] byteCipherText = cipher.doFinal(message.getBytes());

		//Collect result
		EncryptedResource or = new EncryptedResource();
		or.setCypheredText(new Base64Binary(byteCipherText));
		return or;
	}
	
	private Resource doSymetricDecryption(EncryptedResource ir, Base64Binary key, String encrytionAlgorithm) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(encrytionAlgorithm);

		//configure cipher
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getVal(), encrytionAlgorithm) );
		//Encrypt
		byte[] clearText = cipher.doFinal(ir.getCypheredText().getVal());

		//Collect result
		// deserialize Resource
		Resource or = (Resource) ProjectActivator.serializer.getObject().deserialize(new String(clearText,Charset.forName("UTF8")));
		
		return or;
	}
}

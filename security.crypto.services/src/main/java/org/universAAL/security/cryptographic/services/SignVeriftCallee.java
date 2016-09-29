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

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
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
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.cryptographic.Encryption;
import org.universAAL.ontology.cryptographic.SignedResource;

/**
 * @author amedrano
 *
 */
public class SignVeriftCallee extends ServiceCallee {

	/**
	 * @param context
	 * @param realizedServices
	 */
	public SignVeriftCallee(ModuleContext context,
			ServiceProfile[] realizedServices) {
		super(context, realizedServices);
	}

	/**
	 * @param context
	 * @param realizedServices
	 * @param throwOnError
	 */
	public SignVeriftCallee(ModuleContext context,
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
		if (call.getProcessURI().contains("sign")){
			Resource r = (Resource) call.getInputValue(SignVerifyProfile.CLEAR_RESOURCE);
			AsymmetricEncryption enc = (AsymmetricEncryption) call.getInputValue(SignVerifyProfile.ENC_METHOD);
			Digest dig = (Digest) call.getInputValue(SignVerifyProfile.DIG_METHOD);
			Base64Binary key = EncryptionServiceCallee.resolveKey(enc.getKeyRing()[0]);
			try {
				//Digest
				Base64Binary hash = DigestServiceCallee.digestResource(r, dig);
				//Encrypt
				Base64Binary sign = encrypt(enc, key, hash);
				
				//set up the result
				SignedResource sr = new SignedResource();
				sr.setSignedResource(r);
				sr.setSignature(new Base64Binary[]{sign});
				sr.setDigest(dig);
				
				//create copy without the keyring
				AsymmetricEncryption method = (AsymmetricEncryption) enc.deepCopy();
				method.changeProperty(AsymmetricEncryption.PROP_KEY_RING, null);
				method.changeProperty(AsymmetricEncryption.PROP_KEY, null);
				
				ServiceResponse sresp = new ServiceResponse(CallStatus.succeeded);
				sresp.addOutput(new ProcessOutput(SignVerifyProfile.SIGNED_RESOURCE, sr));
				return sresp;
			} catch (Exception e) {
				LogUtils.logError(owner, getClass(), "serviceResponse", new String[]{"un expected error."}, e);
				return new ServiceResponse(CallStatus.serviceSpecificFailure);
			}
		}
		else {
			SignedResource sr = (SignedResource) call.getInputValue(SignVerifyProfile.SIGNED_RESOURCE);
			AsymmetricEncryption enc = (AsymmetricEncryption) call.getInputValue(SignVerifyProfile.ENC_METHOD);
			Digest dig = (Digest) call.getInputValue(SignVerifyProfile.DIG_METHOD);
			
			Base64Binary key;
			if (call.getProcessURI().contains(SignVerifyProfile.VERIFY_EMBEDDED)){
				key = EncryptionServiceCallee.resolveKey(sr.getAsymmetric().getKeyRing()[0]);
			}else if (call.getProcessURI().contains(SignVerifyProfile.VERIFY_EXTERNAL)){
				key = EncryptionServiceCallee.resolveKey(enc.getKeyRing()[0]);
			}
			else {
				//PANIC!
				LogUtils.logError(owner, getClass(), "handleCall", "Should not reach here this");
				return new ServiceResponse(CallStatus.noMatchingServiceFound);
			}
			
			try {
				//Digest
				Base64Binary hash = DigestServiceCallee.digestResource(sr.getSignedResource(), dig);
				
				//check signatures
				Boolean result = Boolean.FALSE;
				Base64Binary[] signatures = sr.getSignature();
				for (int i = 0; i < signatures.length; i++) {
					Base64Binary signedHash = decrypt(enc, key, signatures[i]);
					if (signedHash.equals(hash)){
						result = Boolean.TRUE;
					}
				}
				
				//set up the result
				ServiceResponse sresp = new ServiceResponse(CallStatus.succeeded);
				sresp.addOutput(new ProcessOutput(SignVerifyProfile.RESULT, result));
				return sresp;
			} catch (Exception e) {
				LogUtils.logError(owner, getClass(), "serviceResponse", new String[]{"un expected error."}, e);
				return new ServiceResponse(CallStatus.serviceSpecificFailure);
			}
		}
	}

	static Base64Binary decrypt(AsymmetricEncryption enc, Base64Binary key,
			Base64Binary cleartext) throws GeneralSecurityException {
		String alg = EncryptionServiceCallee.getJavaCipherProviderFromEncryption(enc);
		Cipher cipher = Cipher.getInstance(alg);

		// configure cipher
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getVal(),
				alg));
		// Encrypt
		byte[] byteCipherText = cipher.doFinal(cleartext.getVal());

		return new Base64Binary(byteCipherText);
	}

	static Base64Binary encrypt(Encryption enc, Base64Binary key, Base64Binary cleartext) throws GeneralSecurityException{
		String alg = EncryptionServiceCallee.getJavaCipherProviderFromEncryption(enc);
		Cipher cipher = Cipher.getInstance(alg);

		// configure cipher
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getVal(),
				alg));
		// Encrypt
		byte[] byteCipherText = cipher.doFinal(cleartext.getVal());

		return new Base64Binary(byteCipherText);
	}
}

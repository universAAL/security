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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

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
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.cryptographic.SignedResource;
import org.universAAL.ontology.cryptographic.asymmetric.RSA;
import org.universAAL.ontology.cryptographic.digest.SecureHashAlgorithm;

/**
 * @author amedrano
 *
 */
public class SignVerifyCallee extends ServiceCallee {

	/**
	 * @param context
	 * @param realizedServices
	 */
	public SignVerifyCallee(ModuleContext context, ServiceProfile[] realizedServices) {
		super(context, realizedServices);
	}

	/**
	 * @param context
	 * @param realizedServices
	 * @param throwOnError
	 */
	public SignVerifyCallee(ModuleContext context, ServiceProfile[] realizedServices, boolean throwOnError) {
		super(context, realizedServices, throwOnError);
	}

	/** {@inheritDoc} */
	@Override
	public void communicationChannelBroken() {

	}

	/** {@inheritDoc} */
	@Override
	public ServiceResponse handleCall(ServiceCall call) {
		if (call.getProcessURI().contains("sign")) {
			Resource r = (Resource) call.getInputValue(SignVerifyProfiles.CLEAR_RESOURCE);
			AsymmetricEncryption enc = (AsymmetricEncryption) call.getInputValue(SignVerifyProfiles.ENC_METHOD);
			Digest dig = (Digest) call.getInputValue(SignVerifyProfiles.DIG_METHOD);

			Base64Binary key = ((KeyRing) enc.getKeyRing()[0]).getPrivateKey();
			try {
				SignedResource sr = sign(r, dig, enc, key);

				ServiceResponse sresp = new ServiceResponse(CallStatus.succeeded);
				sresp.addOutput(new ProcessOutput(SignVerifyProfiles.SIGNED_RESOURCE, sr));
				return sresp;
			} catch (Exception e) {
				LogUtils.logError(owner, getClass(), "serviceResponse", new String[] { "un expected error." }, e);
				return new ServiceResponse(CallStatus.serviceSpecificFailure);
			}
		} else {
			SignedResource sr = (SignedResource) call.getInputValue(SignVerifyProfiles.SIGNED_RESOURCE);
			AsymmetricEncryption enc = (AsymmetricEncryption) call.getInputValue(SignVerifyProfiles.ENC_METHOD);
			if (enc == null) {
				enc = sr.getAsymmetric();
			}
			Digest dig = sr.getDigest();

			if (enc.getKeyRing() == null || enc.getKeyRing().length == 0 || enc.getKeyRing()[0] == null) {
				// PANIC!
				LogUtils.logError(owner, getClass(), "handleCall",
						"Should not reach here this, missing keyring for verifying.");
				return new ServiceResponse(CallStatus.noMatchingServiceFound);
			}
			KeyRing keyring = enc.getKeyRing()[0];
			try {
				Base64Binary key = keyring.getPublicKey();
				Boolean result = verify(sr, dig, enc, key);
				ServiceResponse sresp = new ServiceResponse(CallStatus.succeeded);
				sresp.addOutput(new ProcessOutput(SignVerifyProfiles.RESULT, result));
				return sresp;
			} catch (Exception e) {
				LogUtils.logError(owner, getClass(), "serviceResponse", new String[] { "un expected error." }, e);
				return new ServiceResponse(CallStatus.serviceSpecificFailure);
			}
		}
	}

	static private Resource strip4specialCase(Resource r) {
		if (ManagedIndividual.checkMembership(SignedResource.MY_URI, r)) {
			/*
			 * you are about to sign / verify a signed resource, due to loopy
			 * reasons we need to strip the signedResource intrinsic properties
			 * before proceeding.
			 */
			Resource copy = r.deepCopy();
			copy.changeProperty(SignedResource.PROP_ASYMMETRIC, null);
			copy.changeProperty(SignedResource.PROP_DIGEST, null);
			copy.changeProperty(SignedResource.PROP_SIGNATURE, null);
			copy.changeProperty(SignedResource.PROP_SIGNED_RESOURCE, null);
		}
		return r;
	}

	static SignedResource sign(Resource r, Digest dig, AsymmetricEncryption enc, Base64Binary privateKey)
			throws GeneralSecurityException {
		r = strip4specialCase(r);
		// Serialize Resource
		String message = ProjectActivator.serializer.getObject().serialize(r);

		// prepare Java Signature
		Signature s = getSignature(dig, enc);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey.getVal());
		KeyFactory keyFactory = KeyFactory
				.getInstance(EncryptionServiceCallee.getJavaCipherProviderFromEncryption(enc));
		PrivateKey prKey = keyFactory.generatePrivate(keySpec);
		s.initSign(prKey);
		s.update(message.getBytes());

		// set up the result
		SignedResource sr = new SignedResource();
		sr.setSignedResource(r);
		sr.setSignature(new Base64Binary[] { new Base64Binary(s.sign()) });
		sr.setDigest(dig);

		// create copy without the keyring
		AsymmetricEncryption method = (AsymmetricEncryption) enc.deepCopy();
		method.changeProperty(AsymmetricEncryption.PROP_KEY_RING, null);
		method.changeProperty(AsymmetricEncryption.PROP_KEY, null);
		sr.setAsymmetric(method);
		return sr;
	}

	static Boolean verify(SignedResource sr, Digest dig, AsymmetricEncryption enc, Base64Binary publicKey)
			throws GeneralSecurityException {
		// Digest
		Resource r = strip4specialCase(sr.getSignedResource());
		// Serialize Resource
		String message = ProjectActivator.serializer.getObject().serialize(r);

		// prepare Java Verification
		Signature s = getSignature(dig, enc);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey.getVal());
		KeyFactory keyFactory = KeyFactory
				.getInstance(EncryptionServiceCallee.getJavaCipherProviderFromEncryption(enc));
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		s.initVerify(pubKey);
		s.update(message.getBytes());

		// check signatures
		Boolean result = Boolean.FALSE;
		List signatures = sr.getSignature();
		for (Object sign : signatures) {
			if (s.verify(((Base64Binary) sign).getVal())) {
				result = Boolean.TRUE;
			}
		}
		return result;
	}

	static Signature getSignature(Digest dig, AsymmetricEncryption asy) throws NoSuchAlgorithmException {
		String dName = "";
		String aName = "";
		if (dig == null) {
			dName = "NONE";
		} else if (dig.equals(org.universAAL.ontology.cryptographic.digest.MessageDigest.IND_MD2)) {
			dName = "MD2";
		}
		if (dig.equals(org.universAAL.ontology.cryptographic.digest.MessageDigest.IND_MD5)) {
			dName = "MD5";
		}
		if (dig.equals(SecureHashAlgorithm.IND_SHA)) {
			dName = "SHA1";
		}
		if (dig.equals(SecureHashAlgorithm.IND_SHA256)) {
			dName = "SHA256";
		}
		if (dig.equals(SecureHashAlgorithm.IND_SHA384)) {
			dName = "SHA384";
		}
		if (dig.equals(SecureHashAlgorithm.IND_SHA512)) {
			dName = "SHA512";
		}
		if (ManagedIndividual.checkMembership(RSA.MY_URI, asy)) {
			aName = "RSA";
		}

		return Signature.getInstance(dName + "with" + aName);
	}

}

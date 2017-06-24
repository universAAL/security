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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;

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
import org.universAAL.ontology.cryptographic.DestinataryEncryptedSessionKey;
import org.universAAL.ontology.cryptographic.EncryptedResource;
import org.universAAL.ontology.cryptographic.Encryption;
import org.universAAL.ontology.cryptographic.EncryptionKey;
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.cryptographic.MultidestinationEncryptedResource;
import org.universAAL.ontology.cryptographic.SimpleKey;
import org.universAAL.ontology.cryptographic.SymmetricEncryption;
import org.universAAL.ontology.cryptographic.symmetric.AES;

/**
 * @author amedrano
 *
 */
public class MultiDestinationCallee extends ServiceCallee {

	/**
	 * @param context
	 * @param realizedServices
	 */
	public MultiDestinationCallee(ModuleContext context, ServiceProfile[] realizedServices) {
		super(context, realizedServices);
	}

	/**
	 * @param context
	 * @param realizedServices
	 * @param throwOnError
	 */
	public MultiDestinationCallee(ModuleContext context, ServiceProfile[] realizedServices, boolean throwOnError) {
		super(context, realizedServices, throwOnError);
	}

	/** {@inheritDoc} */
	@Override
	public void communicationChannelBroken() {

	}

	/** {@inheritDoc} */
	@Override
	public ServiceResponse handleCall(ServiceCall call) {

		String proc = call.getProcessURI();

		KeyRing keyring = (KeyRing) call.getInputValue(MultiDestinationProfiles.PARAM_KEY_RING);

		if (proc.contains(MultiDestinationProfiles.PROCESS_CREATE)) {
			Resource r = (Resource) call.getInputValue(MultiDestinationProfiles.PARAM_RESOURCE);
			SymmetricEncryption se = (SymmetricEncryption) call
					.getInputValue(MultiDestinationProfiles.PARAM_METHOD_LVL1);
			Object lvl2 = call.getInputValue(MultiDestinationProfiles.PARAM_METHOD_LVL2);
			List<AsymmetricEncryption> ael;
			if (lvl2 instanceof List) {
				ael = (List<AsymmetricEncryption>) lvl2;
			} else if (lvl2 instanceof AsymmetricEncryption) {
				ael = new ArrayList<AsymmetricEncryption>();
				ael.add((AsymmetricEncryption) lvl2);
			} else {
				ael = Collections.EMPTY_LIST;
			}

			MultidestinationEncryptedResource res = createMDER(r, se, ael);
			ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
			sr.addOutput(new ProcessOutput(MultiDestinationProfiles.PARAM_ENCRYPTED_RESOURCE, res));
			return sr;
		}
		if (proc.contains(MultiDestinationProfiles.PROCESS_ADD_DEST)) {
			MultidestinationEncryptedResource mder = (MultidestinationEncryptedResource) call
					.getInputValue(MultiDestinationProfiles.PARAM_ENCRYPTED_RESOURCE);

			List<AsymmetricEncryption> destinations;
			Object in = call.getInputValue(MultiDestinationProfiles.PARAM_METHOD_LVL2);
			if (in instanceof List) {
				destinations = (List<AsymmetricEncryption>) in;
			} else if (in instanceof AsymmetricEncryption) {
				destinations = new ArrayList<AsymmetricEncryption>();
				destinations.add((AsymmetricEncryption) in);
			} else {
				destinations = Collections.EMPTY_LIST;
			}

			addToMDERDest(mder, keyring, destinations);
			ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
			sr.addOutput(new ProcessOutput(MultiDestinationProfiles.PARAM_ENCRYPTED_RESOURCE, mder));
			return sr;
		}
		if (proc.contains(MultiDestinationProfiles.PROCESS_REMOVE_DEST)) {
			MultidestinationEncryptedResource mder = (MultidestinationEncryptedResource) call
					.getInputValue(MultiDestinationProfiles.PARAM_ENCRYPTED_RESOURCE);
			List<DestinataryEncryptedSessionKey> destinations;
			Object in = call.getInputValue(MultiDestinationProfiles.PARAM_DESTINATION);
			if (in instanceof List) {
				destinations = (List<DestinataryEncryptedSessionKey>) in;
			} else if (in instanceof DestinataryEncryptedSessionKey) {
				destinations = new ArrayList<DestinataryEncryptedSessionKey>();
				destinations.add((DestinataryEncryptedSessionKey) in);
			} else {
				destinations = Collections.EMPTY_LIST;
			}

			removeDESK(mder, keyring, destinations);
			ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
			sr.addOutput(new ProcessOutput(MultiDestinationProfiles.PARAM_ENCRYPTED_RESOURCE, mder));
			return sr;
		}
		if (proc.contains(MultiDestinationProfiles.PROCESS_DECRYPT)) {
			MultidestinationEncryptedResource mder = (MultidestinationEncryptedResource) call
					.getInputValue(MultiDestinationProfiles.PARAM_ENCRYPTED_RESOURCE);
			Resource res = decrypt(mder, keyring);
			ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
			sr.addOutput(new ProcessOutput(MultiDestinationProfiles.PARAM_RESOURCE, res));
			return sr;
		}
		return new ServiceResponse(CallStatus.noMatchingServiceFound);
	}

	static MultidestinationEncryptedResource createMDER(Resource r, SymmetricEncryption se,
			List<AsymmetricEncryption> ael) {

		try {
			/*
			 * Resolve Session key
			 */
			SimpleKey sessionKey;
			if (se == null) {
				se = new AES(); // default symmetric encryption.
			}
			sessionKey = se.getSimpleKey();
			if (sessionKey != null && !sessionKey.hasProperty(SimpleKey.PROP_KEY_TEXT)) {
				// generate a new session key using the given keylength as guide
				sessionKey = EncryptionServiceCallee.generateSymmetricKey(se,
						sessionKey.getProperty(SimpleKey.PROP_KEY_LENGTH));
			} else {
				sessionKey = EncryptionServiceCallee.generateSymmetricKey(se, null);
			}

			/*
			 * Encrypt Resource with Session key
			 */
			EncryptedResource er = EncryptionServiceCallee.doEncryption(r, sessionKey.getKeyText(), se);

			/*
			 * encrypt Session key for all destinataries
			 */
			List<DestinataryEncryptedSessionKey> destinations = new ArrayList<DestinataryEncryptedSessionKey>();
			for (AsymmetricEncryption ae : ael) {
				AsymmetricEncryption cleanAE = (AsymmetricEncryption) ae.deepCopy();
				cleanAE.changeProperty(Encryption.PROP_KEY, null);
				cleanAE.changeProperty(AsymmetricEncryption.PROP_KEY_RING, null);
				KeyRing[] krs = ae.getKeyRing();
				for (int i = 0; i < krs.length; i++) {
					try {
						DestinataryEncryptedSessionKey td = new DestinataryEncryptedSessionKey();
						td.setEncryption(cleanAE);
						td.setCypheredText(encryptSessionKey(sessionKey.getKeyText(), cleanAE, krs[i].getPublicKey()));
						destinations.add(td);
					} catch (Exception e) {
						LogUtils.logError(ProjectActivator.context, MultiDestinationCallee.class, "createMDER",
								new String[] { "Could not process one desinatary" }, e);
					}
				}
			}

			/*
			 * Construct MDER
			 */
			MultidestinationEncryptedResource mder = new MultidestinationEncryptedResource();
			mder.setEncryption(er.getEncryption());
			mder.setCypheredText(er.getCypheredText());
			if (destinations.size() == 1) {
				mder.changeProperty(MultidestinationEncryptedResource.PROP_DESTINATARIES, destinations.get(0));
			} else if (destinations.size() > 1) {
				mder.changeProperty(MultidestinationEncryptedResource.PROP_DESTINATARIES, destinations);
			}

			return mder;
		} catch (Exception e) {
			LogUtils.logError(ProjectActivator.context, MultiDestinationCallee.class, "createMDER",
					new String[] { "Could not encrypt Resource" }, e);
			return null;
		}
	}

	static void addToMDERDest(MultidestinationEncryptedResource mder, KeyRing requesterKr,
			List<AsymmetricEncryption> newDests) {
		// TODO: TO be completed
		// REMEMBER TO CHECK each destination is not already added.
	}

	static void removeDESK(MultidestinationEncryptedResource mder, KeyRing keyring,
			List<DestinataryEncryptedSessionKey> destinations) {
		// TODO: To be Completed
	}

	static Resource decrypt(MultidestinationEncryptedResource mder, KeyRing keyring) {
		SimpleKey sk = decryptSessionKey(mder, keyring);
		if (sk != null) {
			try {
				return EncryptionServiceCallee.doDecryption(mder, sk.getKeyText(),
						(SymmetricEncryption) mder.getEncryption());
			} catch (Exception e) {
				LogUtils.logError(ProjectActivator.context, MultiDestinationCallee.class, "decrypt",
						new String[] { "unable to decrypt" }, e);
			}
		}
		return null;
	}

	static Base64Binary encryptSessionKey(Base64Binary mes, AsymmetricEncryption algorithm, Base64Binary publicKey)
			throws GeneralSecurityException {
		String alg = EncryptionServiceCallee.getJavaCipherProviderFromEncryption(algorithm);
		Cipher cipher = Cipher.getInstance(alg);

		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey.getVal());
		KeyFactory keyFactory = KeyFactory.getInstance(alg);
		PublicKey puKey = keyFactory.generatePublic(keySpec);

		// configure cipher
		cipher.init(Cipher.ENCRYPT_MODE, puKey);
		// Encrypt
		return new Base64Binary(cipher.doFinal(mes.getVal()));

	}

	static SimpleKey decryptSessionKey(MultidestinationEncryptedResource mder, KeyRing keyring) {

		List<DestinataryEncryptedSessionKey> lodesk;
		Object tmp = mder.getProperty(MultidestinationEncryptedResource.PROP_DESTINATARIES);
		if (tmp instanceof DestinataryEncryptedSessionKey) {
			lodesk = new ArrayList<DestinataryEncryptedSessionKey>();
			lodesk.add((DestinataryEncryptedSessionKey) tmp);
		} else if (tmp instanceof List) {
			lodesk = (List<DestinataryEncryptedSessionKey>) tmp;
		} else {
			lodesk = Collections.EMPTY_LIST;
		}
		for (DestinataryEncryptedSessionKey desk : lodesk) {
			try {
				// TODO: for more flexible asymmetric decryption call service.
				String alg = EncryptionServiceCallee.getJavaCipherProviderFromEncryption(desk.getEncryption());
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyring.getPrivateKey().getVal());
				KeyFactory keyFactory = KeyFactory.getInstance(alg);
				PrivateKey prKey = keyFactory.generatePrivate(keySpec);
				Cipher cipher = Cipher.getInstance(alg);
				cipher.init(Cipher.DECRYPT_MODE, prKey);
				Base64Binary sk = new Base64Binary(cipher.doFinal(desk.getCypheredText().getVal()));
				// Base64Binary sk = encryptSessionKey(Cipher.DECRYPT_MODE,
				// desk.getCypheredText(), (AsymmetricEncryption)
				// desk.getEncryption(), keyring.getPrivateKey());
				if (sk != null) {
					SimpleKey ssk = new SimpleKey();
					ssk.setKeyText(sk);
					return ssk;
				}
			} catch (Exception e) {
				continue;
			}
		}

		return null;
	}
}

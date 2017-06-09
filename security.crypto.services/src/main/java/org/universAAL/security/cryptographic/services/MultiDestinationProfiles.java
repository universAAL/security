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

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.owl.SimpleOntology;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.rdf.ResourceFactory;
import org.universAAL.middleware.rdf.TypeMapper;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.DestinataryEncryptedSessionKey;
import org.universAAL.ontology.cryptographic.EncryptedResource;
import org.universAAL.ontology.cryptographic.EncryptionService;
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.cryptographic.MultidestinationEncryptedResource;
import org.universAAL.ontology.cryptographic.SymmetricEncryption;

/**
 * @author amedrano
 *
 */
public class MultiDestinationProfiles extends EncryptionService {
	static final ServiceProfile[] profs = new ServiceProfile[4];

	static private final String NAMESPACE = "http://security.universAAL.org/MultiDestinationServices#";

	public static String MY_URI = NAMESPACE + "MultiDestinationEncryptionSerives";

	static final String PROCESS_CREATE = NAMESPACE + "createNewMultiDestinationEncryptedResource";
	static final String PROCESS_ADD_DEST = NAMESPACE + "addDestination2MultiDestinationEncryptedResource";
	static final String PROCESS_REMOVE_DEST = NAMESPACE + "removeDestinationFromMultiDestinationEncryptedResource";
	static final String PROCESS_DECRYPT = NAMESPACE + "decryptMultiDestinationEncryptedResource";

	static final String PARAM_METHOD_LVL1 = NAMESPACE + "symmetricEncryptionMethod";

	static final String PARAM_METHOD_LVL2 = NAMESPACE + "asymmetricEncryptionMethod";

	static final String PARAM_KEY_RING = NAMESPACE + "keyRings";

	static final String PARAM_RESOURCE = NAMESPACE + "resource2Encrypt";

	static final String PARAM_ENCRYPTED_RESOURCE = NAMESPACE + "encryptedMultidestinationResource";

	static final String PARAM_DESTINATION = NAMESPACE + "destinationSessionKey";

	public MultiDestinationProfiles() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param uri
	 */
	public MultiDestinationProfiles(String uri) {
		super(uri);
		// TODO Auto-generated constructor stub
	}

	/** {@inheritDoc} */
	@Override
	public String getClassURI() {
		return MY_URI;
	}

	static void initialize(ModuleContext mc) {
		OntologyManagement.getInstance().register(mc,
				new SimpleOntology(MY_URI, EncryptionService.MY_URI, new ResourceFactory() {

					public Resource createInstance(String classURI, String instanceURI, int factoryIndex) {
						return new MultiDestinationProfiles(instanceURI);
					}
				}));

		/*
		 * Service Profiles
		 */
		// Create new MDR
		MultiDestinationProfiles create = new MultiDestinationProfiles(PROCESS_CREATE);
		create.addFilteringInput(PARAM_METHOD_LVL1, SymmetricEncryption.MY_URI, 0, 1,
				new String[] { EncryptionService.PROP_ENCRYPTED_RESOURCE, EncryptedResource.PROP_ENCRYPTION });
		create.addFilteringInput(PARAM_METHOD_LVL2, AsymmetricEncryption.MY_URI, 1, -1,
				new String[] { EncryptionService.PROP_ENCRYPTION });
		// create.addFilteringInput(PARAM_KEY_RING, KeyRing.MY_URI, 1, -1, new
		// String []
		// {EncryptionService.PROP_ENCRYPTION,AsymmetricEncryption.PROP_KEY_RING});
		// TODO: Asymmetric(s) should have keyring(s)
		// TODO: restriction all Keyrings must have PublicKey
		create.addFilteringInput(PARAM_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1,
				new String[] { EncryptionService.PROP_ENCRYPTS });
		create.addOutput(PARAM_ENCRYPTED_RESOURCE, MultidestinationEncryptedResource.MY_URI, 1, 1,
				new String[] { EncryptionService.PROP_ENCRYPTED_RESOURCE });
		profs[0] = create.myProfile;

		// add new Destinations to MDR
		MultiDestinationProfiles add = new MultiDestinationProfiles(PROCESS_ADD_DEST);
		add.addFilteringInput(PARAM_ENCRYPTED_RESOURCE, MultidestinationEncryptedResource.MY_URI, 1, 1,
				new String[] { EncryptionService.PROP_ENCRYPTED_RESOURCE });
		// Key ring to decrypt session key TODO: requires private Key
		add.addFilteringInput(PARAM_KEY_RING, KeyRing.MY_URI, 1, 1,
				new String[] { EncryptionService.PROP_ENCRYPTION, AsymmetricEncryption.PROP_KEY_RING });
		// Effect is to add a new DestinataryEncryptionSessionKey
		add.addInputWithAddEffect(PARAM_DESTINATION, DestinataryEncryptedSessionKey.MY_URI, 1, -1, new String[] {
				EncryptionService.PROP_ENCRYPTED_RESOURCE, MultidestinationEncryptedResource.PROP_DESTINATARIES });
		// For the destination, we need the corresponding keyrings TODO: all
		// these need public keys
		add.addFilteringInput(PARAM_METHOD_LVL2, AsymmetricEncryption.MY_URI, 1, -1,
				new String[] { EncryptionService.PROP_ENCRYPTED_RESOURCE,
						MultidestinationEncryptedResource.PROP_DESTINATARIES,
						DestinataryEncryptedSessionKey.PROP_ENCRYPTION });
		add.addOutput(PARAM_ENCRYPTED_RESOURCE, MultidestinationEncryptedResource.MY_URI, 1, -1,
				new String[] { EncryptionService.PROP_ENCRYPTED_RESOURCE });
		profs[1] = add.myProfile;
		// TODO: keyrings can be used with different AsymmetricEncryptions,
		// create similar pattern as for cheate with LVL2.

		// remove Destination from MDR
		// TODO: is it really practical??
		MultiDestinationProfiles rem = new MultiDestinationProfiles(PROCESS_REMOVE_DEST);
		rem.addFilteringInput(PARAM_ENCRYPTED_RESOURCE, MultidestinationEncryptedResource.MY_URI, 1, 1,
				new String[] { EncryptionService.PROP_ENCRYPTED_RESOURCE });
		// Key ring to decrypt session key (for security reasons) TODO: requires
		// private Key
		rem.addFilteringInput(PARAM_KEY_RING, KeyRing.MY_URI, 1, 1,
				new String[] { EncryptionService.PROP_ENCRYPTION, AsymmetricEncryption.PROP_KEY_RING });
		// Effect is to remove a DestinataryEncryptionSessionKey
		rem.addInputWithRemoveEffect(PARAM_DESTINATION, DestinataryEncryptedSessionKey.MY_URI, 1, -1, new String[] {
				EncryptionService.PROP_ENCRYPTED_RESOURCE, MultidestinationEncryptedResource.PROP_DESTINATARIES });
		rem.addOutput(PARAM_ENCRYPTED_RESOURCE, MultidestinationEncryptedResource.MY_URI, 1, 1,
				new String[] { EncryptionService.PROP_ENCRYPTED_RESOURCE });
		profs[2] = rem.myProfile;

		// Decrypt
		MultiDestinationProfiles decrypt = new MultiDestinationProfiles(PROCESS_DECRYPT);
		decrypt.addFilteringInput(PARAM_KEY_RING, KeyRing.MY_URI, 1, 1,
				new String[] { EncryptionService.PROP_ENCRYPTION, AsymmetricEncryption.PROP_KEY_RING });
		// TODO: keyrings can be used with different AsymmetricEncryptions,
		// create similar pattern as for cheate with LVL2.
		decrypt.addFilteringInput(PARAM_ENCRYPTED_RESOURCE, MultidestinationEncryptedResource.MY_URI, 1, 1,
				new String[] { EncryptionService.PROP_ENCRYPTED_RESOURCE });
		decrypt.addOutput(PARAM_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1,
				new String[] { EncryptionService.PROP_ENCRYPTS });

		profs[3] = decrypt.myProfile;
	}
}

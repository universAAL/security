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
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.owl.SimpleOntology;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.rdf.ResourceFactory;
import org.universAAL.middleware.rdf.TypeMapper;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.middleware.xsd.Base64Binary;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.cryptographic.SignAndVerifyService;
import org.universAAL.ontology.cryptographic.SignedResource;

/**
 * @author amedrano
 *
 */
public class SignVerifyProfiles extends SignAndVerifyService {

	static final ServiceProfile[] profs = new ServiceProfile[3];

	static private final String NAMESPACE = "http://security.universAAL.org/JavaDigitalSignatureServices#";
	public static String MY_URI = NAMESPACE + "SignVerifySerive";

	// PARAMETERS
	static final String CLEAR_RESOURCE = NAMESPACE + "clear_resource";
	static final String SIGNED_RESOURCE = NAMESPACE + "signed_resource";
	static final String ENC_METHOD = NAMESPACE + "encryptionMethod";
	static final String DIG_METHOD = NAMESPACE + "digestMethod";
	static final String RESULT = NAMESPACE + "VerifyResult";

	static final String SIGN = NAMESPACE + "signResource";
	static final String VERIFY_EMBEDDED = NAMESPACE + "verifyWithEmbeddedKey";
	static final String VERIFY_EXTERNAL = NAMESPACE + "verifyWithProvidedKey";

	/**
	 *
	 */
	public SignVerifyProfiles() {
	}

	/**
	 * @param uri
	 */
	public SignVerifyProfiles(String uri) {
		super(uri);
	}

	/** {@inheritDoc} */
	@Override
	public String getClassURI() {
		return MY_URI;
	}

	static void initialize(ModuleContext mc) {
		OntologyManagement.getInstance().register(mc,
				new SimpleOntology(MY_URI, SignAndVerifyService.MY_URI, new ResourceFactory() {

					public Resource createInstance(String classURI, String instanceURI, int factoryIndex) {
						return new SignVerifyProfiles(instanceURI);
					}
				}));

		/*
		 * Service Profiles
		 */
		// Sign with given AsymmetricEncryption (should include Keyring) and
		// given Digest Methods
		SignVerifyProfiles sign = new SignVerifyProfiles(SIGN);
		sign.addFilteringInput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1,
				new String[] { PROP_SIGN });
		sign.addFilteringInput(ENC_METHOD, AsymmetricEncryption.MY_URI, 1, 1, new String[] { PROP_ASYMMETRIC });
		sign.addFilteringInput(DIG_METHOD, Digest.MY_URI, 1, 1, new String[] { PROP_DIGEST });
		sign.addOutput(SIGNED_RESOURCE, SignedResource.MY_URI, 1, 1, new String[] { PROP_SIGNED_RESOURCE });
		// Asymmetric has to have the keyring
		sign.addInstanceLevelRestriction(MergedRestriction
				.getAllValuesRestrictionWithCardinality(AsymmetricEncryption.PROP_KEY_RING, KeyRing.MY_URI, 1, 1),
				new String[] { PROP_ASYMMETRIC, PROP_KEY_RING });
		// Additionally the Keyring MUST have a private Key
		sign.addInstanceLevelRestriction(
				MergedRestriction.getAllValuesRestrictionWithCardinality(KeyRing.PROP_PRIVATE_KEY,
						TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1),
				new String[] { PROP_ASYMMETRIC, AsymmetricEncryption.PROP_KEY_RING, KeyRing.PROP_PRIVATE_KEY });

		// TODO expand profile and serviceCallee for multiple signature
		// procedure

		profs[0] = sign.myProfile;

		// Verify Given Signed Resource (public key should be provided through
		// AsymmetricEncryption.key)
		SignVerifyProfiles emVerify = new SignVerifyProfiles(VERIFY_EMBEDDED);
		emVerify.addOutput(RESULT, TypeMapper.getDatatypeURI(Boolean.class), 1, 1,
				new String[] { PROP_VERIFICATION_RESULT });
		emVerify.addFilteringInput(SIGNED_RESOURCE, SignedResource.MY_URI, 1, 1, new String[] { PROP_SIGNED_RESOURCE });
		// emVerify.addFilteringInput(ENC_METHOD, AsymmetricEncryption.MY_URI,
		// 1, 1, new
		// String[]{PROP_SIGNED_RESOURCE,SignedResource.PROP_ASYMMETRIC});
		// emVerify.addFilteringInput(DIG_METHOD, Digest.MY_URI, 1, 1, new
		// String[]{PROP_SIGNED_RESOURCE, SignedResource.PROP_DIGEST});
		// Asymmetric has to have the keyring
		emVerify.addInstanceLevelRestriction(
				MergedRestriction.getAllValuesRestrictionWithCardinality(AsymmetricEncryption.PROP_KEY_RING,
						KeyRing.MY_URI, 1, 1),
				new String[] { PROP_SIGNED_RESOURCE, SignedResource.PROP_ASYMMETRIC, PROP_KEY_RING });
		// Additionally the Keyring MUST have a public Key
		emVerify.addInstanceLevelRestriction(
				MergedRestriction.getAllValuesRestrictionWithCardinality(KeyRing.PROP_PUBLIC_KEY,
						TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1),
				new String[] { PROP_SIGNED_RESOURCE, SignedResource.PROP_ASYMMETRIC, AsymmetricEncryption.PROP_KEY_RING,
						KeyRing.PROP_PUBLIC_KEY });

		profs[1] = emVerify.myProfile;

		// Verify Given Signed Resource using given AsymmetricEncryption (wKey)
		SignVerifyProfiles exVerify = new SignVerifyProfiles(VERIFY_EXTERNAL);
		exVerify.addOutput(RESULT, TypeMapper.getDatatypeURI(Boolean.class), 1, 1,
				new String[] { PROP_VERIFICATION_RESULT });
		exVerify.addFilteringInput(SIGNED_RESOURCE, SignedResource.MY_URI, 1, 1, new String[] { PROP_SIGNED_RESOURCE });
		exVerify.addFilteringInput(ENC_METHOD, AsymmetricEncryption.MY_URI, 1, 1, new String[] { PROP_ASYMMETRIC });
		// exVerify.addFilteringInput(DIG_METHOD, Digest.MY_URI, 1, 1, new
		// String[]{PROP_SIGNED_RESOURCE, SignedResource.PROP_DIGEST});
		// Asymmetric has to have the keyring
		exVerify.addInstanceLevelRestriction(MergedRestriction
				.getAllValuesRestrictionWithCardinality(AsymmetricEncryption.PROP_KEY_RING, KeyRing.MY_URI, 1, 1),
				new String[] { PROP_ASYMMETRIC, PROP_KEY_RING });
		// Additionally the Keyring MUST have a public Key
		exVerify.addInstanceLevelRestriction(
				MergedRestriction.getAllValuesRestrictionWithCardinality(KeyRing.PROP_PUBLIC_KEY,
						TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1),
				new String[] { PROP_ASYMMETRIC, AsymmetricEncryption.PROP_KEY_RING, KeyRing.PROP_PUBLIC_KEY });

		profs[2] = exVerify.myProfile;

		// TODO ADD signature.
	}

}

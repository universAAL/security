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
package org.universAAL.security.delegation;

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
import org.universAAL.ontology.cryptographic.KeyRing;
import org.universAAL.ontology.profile.Profilable;
import org.universAAL.ontology.profile.Profile;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.profile.service.ProfilingService;
import org.universAAL.ontology.security.DelegationForm;
import org.universAAL.ontology.security.Role;
import org.universAAL.ontology.security.SecuritySubprofile;

/**
 * @author amedrano
 *
 */
public class DelegationService extends ProfilingService {
	static final ServiceProfile[] profs = new ServiceProfile[3];
	
	static final String NAMESPACE = "http://security.universAAL.org/Delegation#";
	static final String MY_URI = NAMESPACE + "DelegationService";

	static final String PROC_CREATE = NAMESPACE + "createDelegationForm";
	static final String PROC_ADD = NAMESPACE + "addDelegationFormToDelegateSecuritySubprofile";
	static final String PROC_REVOKE = NAMESPACE + "revokeDelegationForm";

	static final String PARAM_DELEGATION_FORM = NAMESPACE + "delegationForm";
	static final String PARAM_AUTHORISER_USER = NAMESPACE + "authoriserUser";
	static final String PARAM_DELEGATE_USER = NAMESPACE + "delegatedUser";
	static final String PARAM_AUTHORISED_ROLES = NAMESPACE + "delegatedCompetences";
	static final String PARAM_ASYMENTRIC_ENCRYPTION = NAMESPACE + "asymmetricMethodToUseKeyRing";

	/**
	 * 
	 */
	public DelegationService() {
	}

	/**
	 * @param uri
	 */
	public DelegationService(String uri) {
		super(uri);
	}

	/**{@inheritDoc} */
	@Override
	public String getClassURI() {
		return MY_URI;
	}

	static void initialize(ModuleContext mc) {
		OntologyManagement.getInstance().register(mc, 
			new SimpleOntology(MY_URI, ProfilingService.MY_URI, new ResourceFactory() {
		    
		    public Resource createInstance(String classURI, String instanceURI,
			    int factoryIndex) {
			return new DelegationService(instanceURI);
		    }
		}));
		
		//create Delegation Form
		DelegationService create = new DelegationService(PROC_CREATE);
		create.addFilteringInput(PARAM_AUTHORISER_USER, User.MY_URI, 1, 1, new String[]
				{ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE, Profile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_DELEGATED_FORMS, DelegationForm.PROP_AUTHORISER});
		create.addFilteringInput(PARAM_DELEGATE_USER, User.MY_URI, 1, 1, new String[]
				{ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE, Profile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_DELEGATED_FORMS, DelegationForm.PROP_DELEGATE});
		create.addFilteringInput(PARAM_AUTHORISED_ROLES, Role.MY_URI, 1, -1, new String[]
				{ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE, Profile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_DELEGATED_FORMS, DelegationForm.PROP_DELEGATED_COMPETENCES});
		create.addFilteringInput(PARAM_ASYMENTRIC_ENCRYPTION, AsymmetricEncryption.MY_URI, 1, 1, new String[]
				{ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE, Profile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_DELEGATED_FORMS, DelegationForm.PROP_ASYMMETRIC});
		create.addOutput(PARAM_DELEGATION_FORM, DelegationForm.MY_URI, 1, 1, new String[]
				{ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE, Profile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_DELEGATED_FORMS});
		// Asymmetric has to have the keyring
		create.addInstanceLevelRestriction(
				MergedRestriction.getAllValuesRestrictionWithCardinality(AsymmetricEncryption.PROP_KEY_RING, KeyRing.MY_URI, 1, 1),
				new String[]{Profile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_DELEGATED_FORMS, DelegationForm.PROP_ASYMMETRIC,AsymmetricEncryption.PROP_KEY_RING});
			// Additionally the Keyring MUST have a private Key
		create.addInstanceLevelRestriction(
				MergedRestriction.getAllValuesRestrictionWithCardinality(KeyRing.PROP_PRIVATE_KEY, TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1),
				new String[]{Profile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_DELEGATED_FORMS, DelegationForm.PROP_ASYMMETRIC,AsymmetricEncryption.PROP_KEY_RING,KeyRing.PROP_PRIVATE_KEY});
		
		profs[0] = create.myProfile;
		
		// add Delegation form to Delegated User's securitysubprofile
		DelegationService add = new DelegationService(PROC_ADD);
		add.addInputWithAddEffect(PARAM_DELEGATION_FORM, DelegationForm.MY_URI, 1, 1, new String[]
				{ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE, Profile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_DELEGATED_FORMS});
		profs[1] = add.myProfile;
		
		//Delegation form revokation
		DelegationService revoke = new DelegationService(PROC_REVOKE);
		revoke.addInputWithRemoveEffect(PARAM_DELEGATION_FORM, DelegationForm.MY_URI, 1, 1, new String[]
				{ProfilingService.PROP_CONTROLS, Profilable.PROP_HAS_PROFILE, Profile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_DELEGATED_FORMS});
		profs[2] = revoke.myProfile;
	}
	
}

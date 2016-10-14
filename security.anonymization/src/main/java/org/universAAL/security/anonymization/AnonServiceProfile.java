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
package org.universAAL.security.anonymization;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.owl.SimpleOntology;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.rdf.ResourceFactory;
import org.universAAL.middleware.rdf.TypeMapper;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.security.Anonymizable;
import org.universAAL.ontology.security.AnonymizationService;

/**
 * @author amedrano
 *
 */
public class AnonServiceProfile extends AnonymizationService {
	static final ServiceProfile[] profs = new ServiceProfile[2];
	
	static final String NAMESPACE = "http://security.universAAL.org/Anonymization#";
	static final String MY_URI = NAMESPACE + "AnonymizationService";

	static final String PROC_ANON = NAMESPACE +"anonymizeProperty";
	static final String PROC_DEANON = NAMESPACE + "deanonymizeProperty";
	static final String PARAM_METHOD = NAMESPACE + "useEncryptionMethod";
	static final String PARAM_IN_ANONYMIZABLE = NAMESPACE + "anonymizableInput";
	static final String PARAM_PROPERTY = NAMESPACE + "property2Banonized";
	static final String PARAM_OUT_ANONYMIZABLE = NAMESPACE + "anonymizableOutput";
	/**
	 * 
	 */
	public AnonServiceProfile() {
	}

	/**
	 * @param uri
	 */
	public AnonServiceProfile(String uri) {
		super(uri);
	}

	/**{@inheritDoc} */
	@Override
	public String getClassURI() {
		return MY_URI;
	}
	static void initialize(ModuleContext mc) {
		OntologyManagement.getInstance().register(mc, 
			new SimpleOntology(MY_URI, AnonymizationService.MY_URI, new ResourceFactory() {
		    
		    public Resource createInstance(String classURI, String instanceURI,
			    int factoryIndex) {
			return new AnonServiceProfile(instanceURI);
		    }
		}));
		
		//Anonymize Service Profile
		AnonServiceProfile anon = new AnonServiceProfile(PROC_ANON);
		anon.addFilteringInput(PARAM_METHOD, AsymmetricEncryption.MY_URI, 1, -1, new String[]{PROP_ASYMMETRIC_ENCRYPTION});
		//TODO add restriction to force all Asymmetric Keyrings to have public keys
		anon.addFilteringInput(PARAM_IN_ANONYMIZABLE, Anonymizable.MY_URI, 1, 1, new String[]{PROP_ANONYMIZABLE});
		anon.addInputWithChangeEffect(PARAM_PROPERTY, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[]{PROP_ANONYMIZABLE,Anonymizable.PROP_ANNONYMOUS_RESOURCE});
		anon.addOutput(PARAM_OUT_ANONYMIZABLE, Anonymizable.MY_URI, 1, 1, new String[]{PROP_ANONYMIZABLE});
		profs[0] = anon.myProfile;
		
		//Deanonymize Service Profile
		AnonServiceProfile deanon = new AnonServiceProfile(PROC_DEANON);
		anon.addFilteringInput(PARAM_METHOD, AsymmetricEncryption.MY_URI, 1, -1, new String[]{PROP_ASYMMETRIC_ENCRYPTION});
		//TODO add restriction to force all Asymmetric Keyrings to have private keys
		deanon.addFilteringInput(PARAM_IN_ANONYMIZABLE, Anonymizable.MY_URI, 1, 1, new String[]{PROP_ANONYMIZABLE});
		deanon.addOutput(PARAM_OUT_ANONYMIZABLE, Anonymizable.MY_URI, 1, 1, new String[]{PROP_ANONYMIZABLE});
		profs[1] = deanon.myProfile;
	}
}

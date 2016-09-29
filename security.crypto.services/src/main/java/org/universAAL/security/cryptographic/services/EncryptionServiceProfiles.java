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
import org.universAAL.ontology.cryptographic.EncryptedResource;
import org.universAAL.ontology.cryptographic.EncryptionService;
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
public class EncryptionServiceProfiles extends EncryptionService {
	static final ServiceProfile[] profs = new ServiceProfile[16];
	
	static final String NAMESPACE = "http://security.universAAL.org/Cryposervices#";
    public static String MY_URI = NAMESPACE + "SomeDe-EcryptionSerives";
    
    //AES	
    static final String ENCRYPT_AES = NAMESPACE + "encrypt-AES";
    static final String DECRYPT_AES = NAMESPACE + "decrypt-AES";
    static final String DECRYPT_AES_TER = NAMESPACE + "decrypt-AES-throughER";
    static final String DECRYPT_AES_WOM = NAMESPACE + "decrypt-AES-withoutExplicitMethod";

    //Blowfish
    static final String ENCRYPT_BLOWFISH = NAMESPACE + "encrypt-Blowfish";
    static final String DECRYPT_BLOWFISH = NAMESPACE + "decrypt-Blowfish";
    static final String DECRYPT_BLOWFISH_TER = NAMESPACE + "decrypt-Blowfish-throughER";
    static final String DECRYPT_BLOWFISH_WOM = NAMESPACE + "decrypt-Blowfish-withoutExplicitMethod";
    //DES
    static final String ENCRYPT_DES = NAMESPACE + "encrypt-DES";
    static final String DECRYPT_DES = NAMESPACE + "decrypt-DES";
    static final String DECRYPT_DES_TER = NAMESPACE + "decrypt-DES-throughER";
    static final String DECRYPT_DES_WOM = NAMESPACE + "decrypt-DES-withoutExplicitMethod";
    //RSA
    static final String ENCRYPT_RSA = NAMESPACE + "encrypt-RSA";
    static final String DECRYPT_RSA = NAMESPACE + "decrypt-RSA";
    static final String DECRYPT_RSA_TER = NAMESPACE + "decrypt-RSA-throughER";
    static final String DECRYPT_RSA_WOM = NAMESPACE + "decrypt-RSA-withoutExplicitMethod";
    

    static final String CLEAR_RESOURCE = NAMESPACE + "clear_resource";
    static final String ENCRYPTED_RESOURCE = NAMESPACE + "encrypted_resource";
    static final String METHOD = NAMESPACE + "encryptionMethod";
    static final String KEY = NAMESPACE + "encryptionKey";
    
	/**
	 * 
	 */
	public EncryptionServiceProfiles() {
	}

	/**
	 * @param uri
	 */
	public EncryptionServiceProfiles(String uri) {
		super(uri);
	}
	public String getClassURI() {
		return MY_URI;
	}
	
	static void initialize(ModuleContext mc) {
		OntologyManagement.getInstance().register(mc, 
			new SimpleOntology(MY_URI, EncryptionService.MY_URI, new ResourceFactory() {
		    
		    public Resource createInstance(String classURI, String instanceURI,
			    int factoryIndex) {
			return new EncryptionServiceProfiles(instanceURI);
		    }
		}));
		
		
		/*
		 * Service Profiles
		 */
		//AES
			// Encrypt resource using given method
		EncryptionServiceProfiles eAES = new EncryptionServiceProfiles(ENCRYPT_AES);
		eAES.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		eAES.addFilteringInput(METHOD, AES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		eAES.addFilteringInput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		eAES.addOutput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});

		 	// Decrypt encrypted resource using given method, Key through method
		EncryptionServiceProfiles dAES = new EncryptionServiceProfiles(DECRYPT_AES);
		dAES.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dAES.addFilteringInput(METHOD, AES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dAES.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dAES.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		
			// Decrypt encrypted resource using ER method, Key through service method
		EncryptionServiceProfiles dAES_TER = new EncryptionServiceProfiles(DECRYPT_AES_TER);
		dAES_TER.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dAES_TER.addFilteringInput(METHOD, AES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE,EncryptedResource.PROP_ENCRYPTION});
		dAES_TER.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dAES_TER.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});

			// Decrypt encrypted resource using ER method, Key attached to ER Method
		EncryptionServiceProfiles dAES_WOM = new EncryptionServiceProfiles(DECRYPT_AES_WOM);
		dAES_WOM.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE, SymmetricEncryption.PROP_SIMPLE_KEY});
		dAES_WOM.addFilteringInput(METHOD, AES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE,EncryptedResource.PROP_ENCRYPTION});
		dAES_WOM.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dAES_WOM.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		
		int i = 0;
		profs[i+0]=eAES.myProfile;
		profs[i+1]=dAES.myProfile;
		profs[i+2]=dAES_TER.myProfile;
		profs[i+3]=dAES_WOM.myProfile;

		//Blowfish
		EncryptionServiceProfiles eBlow = new EncryptionServiceProfiles(ENCRYPT_BLOWFISH);
		eBlow.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		eBlow.addFilteringInput(METHOD, Blowfish.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		eBlow.addFilteringInput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		eBlow.addOutput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});

		EncryptionServiceProfiles dBlow = new EncryptionServiceProfiles(DECRYPT_BLOWFISH);
		dBlow.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dBlow.addFilteringInput(METHOD, Blowfish.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dBlow.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dBlow.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		

			// Decrypt encrypted resource using ER method, Key through service method
		EncryptionServiceProfiles dBlow_TER = new EncryptionServiceProfiles(DECRYPT_BLOWFISH_TER);
		dBlow_TER.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dBlow_TER.addFilteringInput(METHOD, Blowfish.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE,EncryptedResource.PROP_ENCRYPTION});
		dBlow_TER.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dBlow_TER.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
	
			// Decrypt encrypted resource using ER method, Key attached to ER Method
		EncryptionServiceProfiles dBlow_WOM = new EncryptionServiceProfiles(DECRYPT_BLOWFISH_WOM);
		dBlow_WOM.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE, SymmetricEncryption.PROP_SIMPLE_KEY});
		dBlow_WOM.addFilteringInput(METHOD, Blowfish.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE,EncryptedResource.PROP_ENCRYPTION});
		dBlow_WOM.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dBlow_WOM.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		
		i = 4;
		profs[i+0]=eBlow.myProfile;
		profs[i+1]=dBlow.myProfile;
		profs[i+2]=dBlow_TER.myProfile;
		profs[i+3]=dBlow_WOM.myProfile;
		
		//DES
		EncryptionServiceProfiles eDES = new EncryptionServiceProfiles(ENCRYPT_DES);
		eDES.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		eDES.addFilteringInput(METHOD, DES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		eDES.addFilteringInput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		eDES.addOutput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});

		EncryptionServiceProfiles dDES = new EncryptionServiceProfiles(DECRYPT_DES);
		dDES.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dDES.addFilteringInput(METHOD, DES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dDES.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dDES.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});

			// Decrypt encrypted resource using ER method, Key through service method
		EncryptionServiceProfiles dDES_TER = new EncryptionServiceProfiles(DECRYPT_DES_TER);
		dAES_TER.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dAES_TER.addFilteringInput(METHOD, DES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE,EncryptedResource.PROP_ENCRYPTION});
		dAES_TER.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dAES_TER.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
	
			// Decrypt encrypted resource using ER method, Key attached to ER Method
		EncryptionServiceProfiles dDES_WOM = new EncryptionServiceProfiles(DECRYPT_DES_WOM);
		dDES_WOM.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE, SymmetricEncryption.PROP_SIMPLE_KEY});
		dDES_WOM.addFilteringInput(METHOD, DES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE,EncryptedResource.PROP_ENCRYPTION});
		dDES_WOM.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dDES_WOM.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		
		i = 8;
		profs[i+0]=eDES.myProfile;
		profs[i+1]=dDES.myProfile;
		profs[i+2]=dDES_TER.myProfile;
		profs[i+3]=dDES_WOM.myProfile;
		
		//RSA
		EncryptionServiceProfiles eRSA = new EncryptionServiceProfiles(ENCRYPT_RSA);
		eRSA.addFilteringInput(KEY, KeyRing.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		eRSA.addFilteringInput(METHOD, RSA.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		eRSA.addFilteringInput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		eRSA.addOutput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});

		EncryptionServiceProfiles dRSA = new EncryptionServiceProfiles(DECRYPT_RSA);
		dRSA.addFilteringInput(KEY, KeyRing.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dRSA.addFilteringInput(METHOD, RSA.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dRSA.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dRSA.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		
	
			// Decrypt encrypted resource using ER method, Key through service method
		EncryptionServiceProfiles dRSA_TER = new EncryptionServiceProfiles(DECRYPT_RSA_TER);
		dRSA_TER.addFilteringInput(KEY, KeyRing.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dRSA_TER.addFilteringInput(METHOD, RSA.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE,EncryptedResource.PROP_ENCRYPTION});
		dRSA_TER.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dRSA_TER.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
	
			// Decrypt encrypted resource using ER method, Key attached to ER Method
		EncryptionServiceProfiles dRSA_WOM = new EncryptionServiceProfiles(DECRYPT_RSA_WOM);
		dRSA_WOM.addFilteringInput(KEY, KeyRing.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE, SymmetricEncryption.PROP_SIMPLE_KEY});
		dRSA_WOM.addFilteringInput(METHOD, RSA.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE,EncryptedResource.PROP_ENCRYPTION});
		dRSA_WOM.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
		dRSA_WOM.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		
		i = 12;
		profs[i+0]=eRSA.myProfile;
		profs[i+1]=dRSA.myProfile;
		profs[i+2]=dRSA_TER.myProfile;
		profs[i+3]=dRSA_WOM.myProfile;
	}
}

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
	static final ServiceProfile[] profs = new ServiceProfile[8];
	
	static final String NAMESPACE = "http://security.universAAL.org/Cryposervices#";
    public static String MY_URI = NAMESPACE + "SomeDe-EcryptionSerives";
    
    //AES	
    static final String ENCRYPT_AES = NAMESPACE + "encrypt-AES";
    static final String DECRYPT_AES = NAMESPACE + "decrypt-AES";

    //Blowfish
    static final String ENCRYPT_BLOWFISH = NAMESPACE + "encrypt-Blowfish";
    static final String DECRYPT_BLOWFISH = NAMESPACE + "decrypt-Blowfish";
    //DES
    static final String ENCRYPT_DES = NAMESPACE + "encrypt-DES";
    static final String DECRYPT_DES = NAMESPACE + "decrypt-DES";
    //RSA
    static final String ENCRYPT_RSA = NAMESPACE + "encrypt-RSA";
    static final String DECRYPT_RSA = NAMESPACE + "decrypt-RSA";
    

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
		EncryptionServiceProfiles eAES = new EncryptionServiceProfiles(ENCRYPT_AES);
		eAES.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		eAES.addFilteringInput(METHOD, AES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		eAES.addFilteringInput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		eAES.addOutput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});

		EncryptionServiceProfiles dAES = new EncryptionServiceProfiles(DECRYPT_AES);
		eAES.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dAES.addFilteringInput(METHOD, AES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dAES.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dAES.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		
		profs[0]=eAES.myProfile;
		profs[1]=dAES.myProfile;

		//Blowfish
		EncryptionServiceProfiles eBlow = new EncryptionServiceProfiles(ENCRYPT_BLOWFISH);
		eBlow.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		eBlow.addFilteringInput(METHOD, Blowfish.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		eBlow.addFilteringInput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		eBlow.addOutput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});

		EncryptionServiceProfiles dBlow = new EncryptionServiceProfiles(DECRYPT_BLOWFISH);
		eBlow.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dBlow.addFilteringInput(METHOD, Blowfish.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dBlow.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dBlow.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		
		profs[2]=eBlow.myProfile;
		profs[3]=dBlow.myProfile;
		
		//DES
		EncryptionServiceProfiles eDES = new EncryptionServiceProfiles(ENCRYPT_DES);
		eDES.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		eDES.addFilteringInput(METHOD, DES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		eDES.addFilteringInput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		eDES.addOutput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});

		EncryptionServiceProfiles dDES = new EncryptionServiceProfiles(DECRYPT_DES);
		eDES.addFilteringInput(KEY, SimpleKey.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dDES.addFilteringInput(METHOD, DES.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dDES.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dDES.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		
		profs[4]=eDES.myProfile;
		profs[5]=dDES.myProfile;
		
		//RSA
		EncryptionServiceProfiles eRSA = new EncryptionServiceProfiles(ENCRYPT_RSA);
		eRSA.addFilteringInput(KEY, KeyRing.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		eRSA.addFilteringInput(METHOD, RSA.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		eRSA.addFilteringInput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		eRSA.addOutput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});

		EncryptionServiceProfiles dRSA = new EncryptionServiceProfiles(DECRYPT_RSA);
		eRSA.addFilteringInput(KEY, KeyRing.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION, SymmetricEncryption.PROP_SIMPLE_KEY});
		dRSA.addFilteringInput(METHOD, RSA.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dRSA.addFilteringInput(ENCRYPTED_RESOURCE, EncryptedResource.MY_URI, 1, 1, new String[] {EncryptionService.PROP_ENCRYPTION});
		dRSA.addOutput(CLEAR_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String[] {EncryptionService.PROP_ENCRYPTS});
		
		profs[6]=eRSA.myProfile;
		profs[7]=dRSA.myProfile;
	}
}

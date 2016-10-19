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

import java.util.Hashtable;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.owl.Enumeration;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.owl.SimpleOntology;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.rdf.ResourceFactory;
import org.universAAL.middleware.rdf.TypeMapper;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.middleware.xsd.Base64Binary;
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.cryptographic.DigestService;
import org.universAAL.ontology.cryptographic.digest.MessageDigest;
import org.universAAL.ontology.cryptographic.digest.SecureHashAlgorithm;

/**
 * @author amedrano
 *
 */
public class DigestServiceProfiles extends DigestService {

	static final ServiceProfile[] profs = new ServiceProfile[1];
	
	static private final String NAMESPACE = "http://security.universAAL.org/JavaDigestServices#";
    public static String MY_URI = NAMESPACE + "JavaDigestAlgorithms";

	private static Hashtable restrictions = new Hashtable();
	
	static final String PROC_DIGEST = NAMESPACE + "digestProcess";
	static final String OUT_DIGEST = NAMESPACE + "digestedOutput";
	static final String IN_RESOURCE = NAMESPACE + "resourceToBeDigested";
	static final String IN_METHOD = NAMESPACE + "digestMethodToUse";

	private static final String PROCESS_INPUT = NAMESPACE + "processInput";;

	/**
	 * 
	 */
	public DigestServiceProfiles() {
	}

	/**
	 * @param uri
	 */
	public DigestServiceProfiles(String uri) {
		super(uri);
	}
	
	public String getClassURI() {
		return MY_URI;
	}
	
	static void initialize(ModuleContext mc) {
		OntologyManagement.getInstance().register(mc, 
			new SimpleOntology(MY_URI, DigestService.MY_URI, new ResourceFactory() {
		    
		    public Resource createInstance(String classURI, String instanceURI,
			    int factoryIndex) {
			return new DigestServiceProfiles(instanceURI);
		    }
		}));
		
		
		/*
		 * Service Profiles
		 */
		
		addRestriction(getClassRestrictionsOnProperty(
				DigestService.MY_URI, PROP_RESOURCE_TO_DIGEST),
				new String[]{PROP_RESOURCE_TO_DIGEST}, restrictions );
		
		addRestriction(getClassRestrictionsOnProperty(
				DigestService.MY_URI, PROP_DIGEST_METHOD),
				new String[]{PROP_DIGEST_METHOD}, restrictions );
		
		addRestriction(getClassRestrictionsOnProperty(
				DigestService.MY_URI, PROP_DIGESTED_TEXT),
				new String[]{PROP_DIGESTED_TEXT}, restrictions );
		
		
		// Hash
		DigestServiceProfiles digestProfile = new DigestServiceProfiles(PROC_DIGEST);
		digestProfile.addOutput(OUT_DIGEST, TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1, new String[] {DigestService.PROP_DIGESTED_TEXT});
		digestProfile.addFilteringInput(IN_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String [] {DigestService.PROP_RESOURCE_TO_DIGEST});
		digestProfile.addFilteringInput(IN_METHOD, Digest.MY_URI, 1, 1, new String [] {DigestService.PROP_DIGEST_METHOD});
		//Method restricted to available instances
		digestProfile.addInstanceLevelRestriction(
				MergedRestriction.getAllValuesRestrictionWithCardinality(
						PROP_DIGEST_METHOD, 
						new Enumeration(
								new Digest[]{
										MessageDigest.IND_MD2,
										MessageDigest.IND_MD5,
										SecureHashAlgorithm.IND_SHA,
										SecureHashAlgorithm.IND_SHA256,
										SecureHashAlgorithm.IND_SHA384,
										SecureHashAlgorithm.IND_SHA512,}
								), 1, 1),
								new String [] {DigestService.PROP_DIGEST_METHOD});
		
		profs[0] = digestProfile.myProfile;
		
		
	}
	
}

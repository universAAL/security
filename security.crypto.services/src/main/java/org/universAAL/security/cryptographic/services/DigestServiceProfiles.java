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
import org.universAAL.middleware.service.owls.process.ProcessInput;
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

	static final ServiceProfile[] profs = new ServiceProfile[6];
	
	static private final String NAMESPACE = "http://security.universAAL.org/JavaDigestServices#";
    public static String MY_URI = NAMESPACE + "JavaDigestAlgorithms";
	static final String DIGEST_MD2 = NAMESPACE + "digestWithMD2";
	static final String DIGEST_MD5 = NAMESPACE + "digestWithMD5";
	static final String DIGEST_SHA = NAMESPACE + "digestWithSHA";
	static final String DIGEST_SHA256 = NAMESPACE + "digestWithSHA256";
	static final String DIGEST_SHA384 = NAMESPACE + "digestWithSHA384";
	static final String DIGEST_SHA512 = NAMESPACE + "digestWithSHA512";
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
		
		
		// MD2 Hash
		DigestServiceProfiles md2 = new DigestServiceProfiles(DIGEST_MD2);
		md2.addOutput(OUT_DIGEST, TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1, new String[] {DigestService.PROP_DIGESTED_TEXT});
		md2.addFilteringInput(IN_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String [] {DigestService.PROP_RESOURCE_TO_DIGEST});
		//Method restricted to MD2 instance
		ProcessInput pi = md2.createInput(IN_METHOD, Digest.MY_URI, 1, 1);
		pi.setParameterValue(MessageDigest.IND_MD2);
		md2.addInstanceLevelRestriction(MergedRestriction.getFixedValueRestriction(DigestService.PROP_DIGEST_METHOD, pi), new String [] {DigestService.PROP_DIGEST_METHOD});
		
		profs[0] = md2.myProfile;
		
		// MD5 Hash
		DigestServiceProfiles md5 = new DigestServiceProfiles(DIGEST_MD5);
		md5.addOutput(OUT_DIGEST, TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1, new String[] {DigestService.PROP_DIGESTED_TEXT});
		md5.addFilteringInput(IN_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String [] {DigestService.PROP_RESOURCE_TO_DIGEST});
		//Method restricted to MD5 instance
		pi = md5.createInput(IN_METHOD, Digest.MY_URI, 1, 1);
		pi.setParameterValue(MessageDigest.IND_MD5);
		md5.addInstanceLevelRestriction(MergedRestriction.getFixedValueRestriction(DigestService.PROP_DIGEST_METHOD, pi), new String [] {DigestService.PROP_DIGEST_METHOD});
		
		profs[1] = md5.myProfile;
		
		// SHA Hash
		DigestServiceProfiles sha = new DigestServiceProfiles(DIGEST_SHA);
		sha.addOutput(OUT_DIGEST, TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1, new String[] {DigestService.PROP_DIGESTED_TEXT});
		sha.addFilteringInput(IN_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String [] {DigestService.PROP_RESOURCE_TO_DIGEST});
		//Method restricted to SHA instance
		pi = sha.createInput(IN_METHOD, Digest.MY_URI, 1, 1);
		pi.setParameterValue(SecureHashAlgorithm.IND_SHA);
		sha.addInstanceLevelRestriction(MergedRestriction.getFixedValueRestriction(DigestService.PROP_DIGEST_METHOD, pi), new String [] {DigestService.PROP_DIGEST_METHOD});
		
		profs[2] = sha.myProfile;
		
		// SHA256 Hash
		DigestServiceProfiles sha2 = new DigestServiceProfiles(DIGEST_SHA256);
		sha2.addOutput(OUT_DIGEST, TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1, new String[] {DigestService.PROP_DIGESTED_TEXT});
		sha2.addFilteringInput(IN_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String [] {DigestService.PROP_RESOURCE_TO_DIGEST});
		//Method restricted to SHA256 instance
		pi = sha2.createInput(IN_METHOD, Digest.MY_URI, 1, 1);
		pi.setParameterValue(SecureHashAlgorithm.IND_SHA256);
		sha2.addInstanceLevelRestriction(MergedRestriction.getFixedValueRestriction(DigestService.PROP_DIGEST_METHOD, pi), new String [] {DigestService.PROP_DIGEST_METHOD});
		
		profs[3] = sha2.myProfile;
		
		// SHA384 Hash
		DigestServiceProfiles sha3 = new DigestServiceProfiles(DIGEST_SHA384);
		sha3.addOutput(OUT_DIGEST, TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1, new String[] {DigestService.PROP_DIGESTED_TEXT});
		sha3.addFilteringInput(IN_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String [] {DigestService.PROP_RESOURCE_TO_DIGEST});
		//Method restricted to SHA384 instance
		pi = sha3.createInput(IN_METHOD, Digest.MY_URI, 1, 1);
		pi.setParameterValue(SecureHashAlgorithm.IND_SHA384);
		sha3.addInstanceLevelRestriction(MergedRestriction.getFixedValueRestriction(DigestService.PROP_DIGEST_METHOD, pi), new String [] {DigestService.PROP_DIGEST_METHOD});
		
		profs[4] = sha3.myProfile;
		
		// SHA512 Hash
		DigestServiceProfiles sha5 = new DigestServiceProfiles(DIGEST_SHA512);
		sha5.addOutput(OUT_DIGEST, TypeMapper.getDatatypeURI(Base64Binary.class), 1, 1, new String[] {DigestService.PROP_DIGESTED_TEXT});
		sha5.addFilteringInput(IN_RESOURCE, TypeMapper.getDatatypeURI(Resource.class), 1, 1, new String [] {DigestService.PROP_RESOURCE_TO_DIGEST});
		//Method restricted to SHA512 instance
		pi = sha5.createInput(IN_METHOD, Digest.MY_URI, 1, 1);
		pi.setParameterValue(SecureHashAlgorithm.IND_SHA512);
		sha5.addInstanceLevelRestriction(MergedRestriction.getFixedValueRestriction(DigestService.PROP_DIGEST_METHOD, pi), new String [] {DigestService.PROP_DIGEST_METHOD});
		
		profs[5] = sha5.myProfile;
		
		
	}
	
}

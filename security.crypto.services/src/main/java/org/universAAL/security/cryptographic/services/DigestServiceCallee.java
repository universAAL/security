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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.cryptographic.digest.SecureHashAlgorithm;

/**
 * @author amedrano
 *
 */
public class DigestServiceCallee extends ServiceCallee {

	/**
	 * @param context
	 * @param realizedServices
	 */
	public DigestServiceCallee(ModuleContext context,
			ServiceProfile[] realizedServices) {
		super(context, realizedServices);
	}

	/**
	 * @param context
	 * @param realizedServices
	 * @param throwOnError
	 */
	public DigestServiceCallee(ModuleContext context,
			ServiceProfile[] realizedServices, boolean throwOnError) {
		super(context, realizedServices, throwOnError);
	}

	/**{@inheritDoc} */
	@Override
	public void communicationChannelBroken() {

	}

	/**{@inheritDoc} */
	@Override
	public ServiceResponse handleCall(ServiceCall call) {
		Resource r = (Resource) call.getInputValue(DigestServiceImpl.IN_RESOURCE);
		Digest d = (Digest) call.getInputValue(DigestServiceImpl.IN_METHOD);
		
		
		
		Base64Binary digest = null;
		try {
			digest = digestResource(r, d);
		} catch (NoSuchAlgorithmException e) {
			LogUtils.logError(owner, getClass(), "handleCall", "The digest algorithm is not found, this should not be possible, check your java version.");
			ServiceResponse sr = new ServiceResponse(CallStatus.serviceSpecificFailure);
			sr.setResourceComment("NoSuchAlgorithmException");
			return sr;
		}
		
		ProcessOutput out = new ProcessOutput(DigestServiceImpl.OUT_DIGEST, digest);
		
		ServiceResponse sr = new ServiceResponse(CallStatus.succeeded);
		sr.addOutput(out);
		return sr;
	}

	static Base64Binary digestResource(Resource r, Digest method) throws NoSuchAlgorithmException{
		MessageDigest md = getMD(method);
		
		// Serialize Resource
		String message = ProjectActivator.serializer.getObject().serialize(r);
		// Digest serialized resource
		byte[] digested = md.digest(message.getBytes());
		
		return new Base64Binary(digested);
		
	}
	
	
	static private MessageDigest getMD(Digest digestAlgorithm)
			throws NoSuchAlgorithmException {
		if (digestAlgorithm.equals(org.universAAL.ontology.cryptographic.digest.MessageDigest.IND_MD2)) {
			return MessageDigest.getInstance("MD2");
		}
		if (digestAlgorithm.equals(org.universAAL.ontology.cryptographic.digest.MessageDigest.IND_MD5)) {
			return MessageDigest.getInstance("MD5");
		}
		if (digestAlgorithm.equals(SecureHashAlgorithm.IND_SHA)) {
			return MessageDigest.getInstance("SHA");
		}
		if (digestAlgorithm.equals(SecureHashAlgorithm.IND_SHA256)) {
			return MessageDigest.getInstance("SHA-256");
		}
		if (digestAlgorithm.equals(SecureHashAlgorithm.IND_SHA384)) {
			return MessageDigest.getInstance("SHA-384");
		}
		if (digestAlgorithm.equals(SecureHashAlgorithm.IND_SHA512)) {
			return MessageDigest.getInstance("SHA-512");
		}
		throw new NoSuchAlgorithmException();
	}
	
}

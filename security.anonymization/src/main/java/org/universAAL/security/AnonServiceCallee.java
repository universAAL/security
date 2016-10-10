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
package org.universAAL.security;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Enumeration;

import org.universAAL.ioc.dependencies.impl.PassiveDependencyProxy;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.serialization.MessageContentSerializer;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceCall;
import org.universAAL.middleware.service.ServiceCallee;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.EncryptedResource;
import org.universAAL.ontology.cryptographic.Encryption;
import org.universAAL.ontology.cryptographic.EncryptionService;
import org.universAAL.ontology.cryptographic.MultidestinationEncryptedResource;
import org.universAAL.ontology.cryptographic.symmetric.AES;

/**
 * @author amedrano
 *
 */
public class AnonServiceCallee extends ServiceCallee {

	private static final String PARAM_ENCRY_RESOURCE_OUT = AnonServiceProfile.NAMESPACE + "paramOutEncryptedResource";

	public static final String PROTOCOL = "activeAnon://";
	
	static PassiveDependencyProxy<MessageContentSerializer> serializer;

	/**
	 * @param context
	 * @param realizedServices
	 */
	public AnonServiceCallee(ModuleContext context,
			ServiceProfile[] realizedServices) {
		super(context, realizedServices);
		serializer = new PassiveDependencyProxy<MessageContentSerializer>(
				context,
				new Object[] { MessageContentSerializer.class.getName() });
	}

	/**
	 * @param context
	 * @param realizedServices
	 * @param throwOnError
	 */
	public AnonServiceCallee(ModuleContext context,
			ServiceProfile[] realizedServices, boolean throwOnError) {
		super(context, realizedServices, throwOnError);
		serializer = new PassiveDependencyProxy<MessageContentSerializer>(
				context,
				new Object[] { MessageContentSerializer.class.getName() });
	}

	/**{@inheritDoc} */
	@Override
	public void communicationChannelBroken() {

	}

	/**{@inheritDoc} */
	@Override
	public ServiceResponse handleCall(ServiceCall call) {
		if (call.getProcessURI().contains(AnonServiceProfile.PROC_ANON)){
			/*
			 * anonymize
			 */
			//gather imputs
			Resource anonymizable = (Resource) call.getInputValue(AnonServiceProfile.PARAM_IN_ANONYMIZABLE);
			Resource propvalue =  (Resource) call.getInputValue(AnonServiceProfile.PARAM_PROPERTY);
			Resource method = (Resource) call.getInputValue(AnonServiceProfile.PARAM_METHOD);
			//create dummy resource to be encrypted
			Resource newPropValue = Resource.getResource(propvalue.getType(), propvalue.getURI());
			//TODO: add option to encrypt the full resource?
			
			//call Multidestination Encryption Service
			EncryptionService encSrv = new EncryptionService();
			encSrv.setEncryption((Encryption) method);
			encSrv.setEncrypts(newPropValue);
			encSrv.addInstanceLevelRestriction(MergedRestriction.getAllValuesRestriction(
					EncryptionService.PROP_ENCRYPTED_RESOURCE, MultidestinationEncryptedResource.MY_URI), 
					new String[]{EncryptionService.PROP_ENCRYPTED_RESOURCE});
			ServiceRequest sr = new ServiceRequest(encSrv, call.getInvolvedUser());
			sr.addValueFilter(new String [] {EncryptionService.PROP_ENCRYPTED_RESOURCE,EncryptedResource.PROP_ENCRYPTION}, new AES());
			sr.addRequiredOutput(PARAM_ENCRY_RESOURCE_OUT, new String [] {EncryptionService.PROP_ENCRYPTED_RESOURCE});
			
			DefaultServiceCaller caller = new DefaultServiceCaller(owner);
			ServiceResponse sresp = caller.call(sr);
			caller.close();
			
			EncryptedResource er = (EncryptedResource) sresp.getOutput(PARAM_ENCRY_RESOURCE_OUT).get(0);
			// serialize to create newURI
			
			try {
				String newURI = flatten2URI(serializer.getObject().serialize(er));
				newPropValue = Resource.getResource(propvalue.getType(), newURI);
			} catch (UnsupportedEncodingException e) {
				LogUtils.logError(owner, getClass(), "attemptDecryption", new String[]{"unable to encode. It seems Your system does not support UTF-8... from when is your system? darkages? "}, e);
				return new ServiceResponse(CallStatus.serviceSpecificFailure);
			}
			
			// substitute property in anonymizable
			Resource newanon = copyWreplacedProperty(anonymizable, propvalue, newPropValue);

			//construct response
			if (newanon != null) {
				ServiceResponse mysrvresp = new ServiceResponse(CallStatus.succeeded);
				mysrvresp.addOutput(AnonServiceProfile.PARAM_OUT_ANONYMIZABLE, newanon);
				return mysrvresp;
			}
			else {
				ServiceResponse mysrvresp = new ServiceResponse(CallStatus.serviceSpecificFailure);
				mysrvresp. setProperty(ServiceResponse.PROP_SERVICE_SPECIFIC_ERROR, "Unable to add new Anonymised property value");
				return mysrvresp;
			}
		}
		if (call.getProcessURI().contains(AnonServiceProfile.PROC_DEANON)){
			/*
			 * deanonymize
			 */
			//gather imputs
			Resource anonymizable = (Resource) call.getInputValue(AnonServiceProfile.PARAM_IN_ANONYMIZABLE);
			AsymmetricEncryption method = (AsymmetricEncryption) call.getInputValue(AnonServiceProfile.PARAM_METHOD);
			
			//create copy
			Resource newanon = anonymizable.deepCopy();
			//search all properties to deanonymize
			Enumeration en = newanon.getPropertyURIs();
			while (en.hasMoreElements() ) {
				String prop = (String) en.nextElement();
				Object propValue = newanon.getProperty(prop);
				if (propValue instanceof Resource 
						&& ((Resource)propValue).getURI().contains(PROTOCOL)){
					newanon.changeProperty(prop, attemptDecryption(method, (Resource)propValue, call.getInvolvedUser()));
				}
			}
			
			//construct response
			ServiceResponse mysrvresp = new ServiceResponse(CallStatus.succeeded);
			mysrvresp.addOutput(AnonServiceProfile.PARAM_OUT_ANONYMIZABLE, newanon);
			return mysrvresp;
		}
		return new ServiceResponse(CallStatus.noMatchingServiceFound);
	}
	
	static Resource copyWreplacedProperty(Resource root, Object orig, Object newPropValue){
		// substitute property in anonymizable
		Resource newanon = root.deepCopy();
		Enumeration en = newanon.getPropertyURIs();
		boolean replaced = false;
		while (en.hasMoreElements() && !replaced) {
			String prop = (String) en.nextElement();
			if (newanon.getProperty(prop).equals(orig)){
				//WARN: This checks the membership of the newPropvalue
				replaced = newanon.changeProperty(prop, newPropValue);
			}
		}
		if (replaced){
			return newanon;
		}
		else {
			return null;
		}
	}
	
	static String flatten2URI(String s) throws UnsupportedEncodingException {
		String newURI = s.replaceAll("\\s+", " ");
		newURI = URLEncoder.encode(newURI, "UTF-8");
		return  AnonServiceCallee.PROTOCOL + newURI;
	}
	
	static String unflattenFromURI(String uri) throws UnsupportedEncodingException{
		String serialized = uri.substring(AnonServiceCallee.PROTOCOL.length(), uri.length());
		return URLDecoder.decode(serialized, "UTF-8");
	}

	private Resource attemptDecryption(AsymmetricEncryption method, Resource encryptedValue, Resource involvedUser){
		//reconstruct original MDER
		String serialized = encryptedValue.getURI();
		try {
			serialized = unflattenFromURI(serialized);
		} catch (UnsupportedEncodingException e) {
			LogUtils.logWarn(owner, getClass(), "attemptDecryption", new String[]{"unable to deconde. It seems Your system does not support UTF-8... from when is your system? darkages? "}, e);
		}
		Resource mder = (Resource) serializer.getObject().deserialize(serialized);
		
		
		//call Multidestination Encryption Service to decrypt
		EncryptionService encSrv = new EncryptionService();
		encSrv.setEncryption((Encryption) method);
		
		ServiceRequest sr = new ServiceRequest(encSrv, involvedUser);
		sr.addValueFilter(new String[]{EncryptionService.PROP_ENCRYPTION,AsymmetricEncryption.PROP_KEY_RING}, method.getProperty(AsymmetricEncryption.PROP_KEY_RING));
		sr.addValueFilter(new String[]{EncryptionService.PROP_ENCRYPTED_RESOURCE}, mder);
		sr.addRequiredOutput(PARAM_ENCRY_RESOURCE_OUT, new String [] {EncryptionService.PROP_ENCRYPTS});
		
		DefaultServiceCaller caller = new DefaultServiceCaller(owner);
		ServiceResponse sresp = caller.call(sr);
		caller.close();
		
		//if successful decryption return deanonymized resource
		if (sresp.getCallStatus().equals(CallStatus.succeeded)) {
			return (Resource) sresp.getOutput(PARAM_ENCRY_RESOURCE_OUT)
					.get(0);
		} else {
			//else return current value
			LogUtils.logDebug(owner, getClass(), "deanonymize", "could not decrypt property value with URI: " + serialized);
			return encryptedValue;
		}
		
	}
}

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

import java.util.List;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceCall;
import org.universAAL.middleware.service.ServiceCallee;
import org.universAAL.middleware.service.ServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.SignAndVerifyService;
import org.universAAL.ontology.cryptographic.SignedResource;
import org.universAAL.ontology.cryptographic.digest.SecureHashAlgorithm;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.DelegationForm;

/**
 * @author amedrano
 *
 */
public class DelegationServieCallee extends ServiceCallee {

	static final String OUT_SIGNED = DelegationService.NAMESPACE + "outputSignedDelegationForm";

	/**
	 * @param context
	 * @param realizedServices
	 */
	public DelegationServieCallee(ModuleContext context,
			ServiceProfile[] realizedServices) {
		super(context, realizedServices);
	}

	/**
	 * @param context
	 * @param realizedServices
	 * @param throwOnError
	 */
	public DelegationServieCallee(ModuleContext context,
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
		String callURI = call.getProcessURI();
		if (callURI.contains(DelegationService.PROC_ADD)){
			DelegationForm df = (DelegationForm) call.getInputValue(DelegationService.PARAM_DELEGATION_FORM);
			if (addDelegationForm(df)){
				return new ServiceResponse(CallStatus.succeeded);
			}else {
				return new ServiceResponse(CallStatus.denied);
			}
		}
		if (callURI.contains(DelegationService.PROC_CREATE)){
			User authoriser = (User) call.getInputValue(DelegationService.PARAM_AUTHORISER_USER); 
			User delegate = (User) call.getInputValue(DelegationService.PARAM_DELEGATE_USER);
			Object role = call.getInputValue(DelegationService.PARAM_AUTHORISED_ROLES);
			AsymmetricEncryption ae = (AsymmetricEncryption) call.getInputValue(DelegationService.PARAM_ASYMENTRIC_ENCRYPTION);
			
			DelegationForm df = createDelegationForm(authoriser, delegate, role, ae);
			ServiceResponse sr;
			if (df != null) {
				sr = new ServiceResponse(CallStatus.succeeded);
				sr.addOutput(DelegationService.PARAM_DELEGATION_FORM, df);
			}else {
				sr = new ServiceResponse(CallStatus.serviceSpecificFailure);
			}
			return sr;
		}
		if (callURI.contains(DelegationService.PROC_REVOKE)){
			DelegationForm df = (DelegationForm) call.getInputValue(DelegationService.PARAM_DELEGATION_FORM);
			if (revokeDelegationForm(df)){
				return new ServiceResponse(CallStatus.succeeded);
			}else {
				return new ServiceResponse(CallStatus.denied);
			}
		}
		return new ServiceResponse(CallStatus.noMatchingServiceFound);
	}

	DelegationForm createDelegationForm(User authoriser, User delegate,
			Object roles, AsymmetricEncryption ae) {
		// TODO Auto-generated method stub
		//compose the DelegationForm
		DelegationForm df = new DelegationForm();
		df.changeProperty(DelegationForm.PROP_AUTHORISER, authoriser);
		df.changeProperty(DelegationForm.PROP_DELEGATE, delegate);
		df.changeProperty(DelegationForm.PROP_DELEGATED_COMPETENCES, roles);
		
		// sing the DF with the given keyring
		
		SignAndVerifyService s = new SignAndVerifyService();
		s.setSign(df);
		s.setAsymmetric(ae);
		s.setDigest(SecureHashAlgorithm.IND_SHA256);
		
		ServiceRequest sr = new ServiceRequest(s, authoriser);
		sr.addRequiredOutput(OUT_SIGNED, new String[]{SignAndVerifyService.PROP_SIGNED_RESOURCE});
		
		ServiceCaller sc = new DefaultServiceCaller(owner);
		ServiceResponse sres = sc.call(sr);
		sc.close();
		
		if (sres.getCallStatus().equals(CallStatus.succeeded)) {
			List result = sres.getOutput(OUT_SIGNED);
			
			SignedResource sigr = (SignedResource) result.get(0);
			
			// set self property + signature
			df.setSignedResource(df);
			df.setSignature(sigr.getSignature());
			df.setAsymmetric(sigr.getAsymmetric());
			df.setDigest(sigr.getDigest());
			return df;
		} else {
			return null;
		}
	}

	boolean addDelegationForm(DelegationForm df) {
		// TODO Auto-generated method stub
		// 
		return false;
	}

	boolean revokeDelegationForm(DelegationForm df) {
		// TODO Auto-generated method stub
		return false;
	}

}

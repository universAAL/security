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

import java.util.ArrayList;
import java.util.List;

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
import org.universAAL.middleware.service.ServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.cryptographic.AsymmetricEncryption;
import org.universAAL.ontology.cryptographic.SignAndVerifyService;
import org.universAAL.ontology.cryptographic.SignedResource;
import org.universAAL.ontology.cryptographic.digest.SecureHashAlgorithm;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.AuthorizationService;
import org.universAAL.ontology.security.DelegationForm;
import org.universAAL.ontology.security.SecuritySubprofile;
import org.universAAL.security.CHeQuerrier;

/**
 * @author amedrano
 *
 */
public class DelegationServieCallee extends ServiceCallee {

	static final String OUT_SIGNED = DelegationService.NAMESPACE + "outputSignedDelegationForm";
	
	private static final String AUX_BAG_OBJECT = DelegationService.NAMESPACE + "auxilaryBagObject";
	private static final String AUX_BAG_PROP =  DelegationService.NAMESPACE + "auxilaryBagProperty";

	private PassiveDependencyProxy<MessageContentSerializer> serializer;

	/**
	 * @param context
	 * @param realizedServices
	 */
	public DelegationServieCallee(ModuleContext context,
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
	public DelegationServieCallee(ModuleContext context,
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
		String callURI = call.getProcessURI();
		if (callURI.contains(DelegationService.PROC_ADD)){
			DelegationForm df = (DelegationForm) call.getInputValue(DelegationService.PARAM_DELEGATION_FORM);
			if (addDelegationForm(df, call.getInvolvedUser())){
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
			if (revokeDelegationForm(df, call.getInvolvedUser())){
				return new ServiceResponse(CallStatus.succeeded);
			}else {
				return new ServiceResponse(CallStatus.denied);
			}
		}
		return new ServiceResponse(CallStatus.noMatchingServiceFound);
	}

	DelegationForm createDelegationForm(User authoriser, User delegate,
			Object roles, AsymmetricEncryption ae) {
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

	boolean addDelegationForm(DelegationForm df, Resource callUser) {
		User cu;
		if (callUser == null || !(callUser instanceof User)){
			cu = (User) df.getProperty(DelegationForm.PROP_AUTHORISER);
		} else{
			cu = (User) callUser;
		}
		
		// check authorisation permissions
		ServiceRequest sr = new ServiceRequest(new AuthorizationService(), callUser);
		sr.addAddEffect(new String[]{AuthorizationService.PROP_ASSET_ACCESS}, df);
		sr.addValueFilter(new String []{AuthorizationService.PROP_CHALLENGER_USER}, cu);
		
		ServiceCaller scall = new DefaultServiceCaller(owner);
		ServiceResponse sresp = scall.call(sr);
		scall.close();
		
		if (!sresp.getCallStatus().equals(CallStatus.succeeded)){
			return false;
		}
		//update the security subprofile of the delegate
		User delegate = (User) df.getProperty(DelegationForm.PROP_DELEGATE);
		SecuritySubprofile ssp = getSecuritySubProfile(delegate);
		Object o = ssp.getProperty(SecuritySubprofile.PROP_DELEGATED_FORMS);
		if (o == null) {
			ssp.changeProperty(SecuritySubprofile.PROP_DELEGATED_FORMS, df);
		}else if (o instanceof List){
			((List)o).add(df);
			ssp.changeProperty(SecuritySubprofile.PROP_DELEGATED_FORMS, o);
		} else {
			ArrayList al = new ArrayList();
			al.add(o);
			al.add(df);
			ssp.changeProperty(SecuritySubprofile.PROP_DELEGATED_FORMS, al);
		}
		updateProperty(ssp, SecuritySubprofile.PROP_DELEGATED_FORMS);
		return true;
	}

	boolean revokeDelegationForm(DelegationForm df, Resource callUser) {
		User cu;
		if (callUser == null || !(callUser instanceof User)){
			cu = (User) df.getProperty(DelegationForm.PROP_AUTHORISER);
		} else{
			cu = (User) callUser;
		}
		
		// check authorisation permissions
		ServiceRequest sr = new ServiceRequest(new AuthorizationService(), callUser);
//		 ServiceRequest req = new ServiceRequest(new ProfilingService(null),null);
//		 MergedRestriction r1 = MergedRestriction.getFixedValueRestriction(<PATHLAST>, <INSTANCE>);
//		 req.getRequestedService().addInstanceLevelRestriction(r1,new String[] { <PATH> });
//		 req.addRemoveEffect(new String[] { <PATH> });
		sr.getRequestedService().addInstanceLevelRestriction(
				MergedRestriction.getFixedValueRestriction(AuthorizationService.PROP_ASSET_ACCESS, df),
				new String[]{AuthorizationService.PROP_ASSET_ACCESS});
		sr.addRemoveEffect(new String[]{AuthorizationService.PROP_ASSET_ACCESS});
		sr.addValueFilter(new String []{AuthorizationService.PROP_CHALLENGER_USER}, cu);
		
		ServiceCaller scall = new DefaultServiceCaller(owner);
		ServiceResponse sresp = scall.call(sr);
		scall.close();
		
		if (!sresp.getCallStatus().equals(CallStatus.succeeded)){
			return false;
		}
		//update the security subprofile of the delegate
		User delegate = (User) df.getProperty(DelegationForm.PROP_DELEGATE);
		SecuritySubprofile ssp = getSecuritySubProfile(delegate);
		Object o = ssp.getProperty(SecuritySubprofile.PROP_DELEGATED_FORMS);
		if (o instanceof List){
			((List)o).remove(df);
			ssp.changeProperty(SecuritySubprofile.PROP_DELEGATED_FORMS, o);
		} else if ((o instanceof DelegationForm)&&(o.equals(df))){
			ssp.changeProperty(SecuritySubprofile.PROP_DELEGATED_FORMS, null);
		} else {
			//no changes to be done.
			return true; 
		}
		updateProperty(ssp, SecuritySubprofile.PROP_DELEGATED_FORMS);
		return true;
	}

	protected SecuritySubprofile getSecuritySubProfile( User usr){
		CHeQuerrier querier = new CHeQuerrier(owner);
		Object o = querier.query(CHeQuerrier.getQuery(CHeQuerrier.getResource("getSecuritySubProfileForUser.sparql"), new String[]{AUX_BAG_OBJECT,AUX_BAG_PROP,usr.getURI()}));
		SecuritySubprofile ssp;
		if (o instanceof SecuritySubprofile){
			ssp = (SecuritySubprofile) o;
		} else if (o instanceof List){
			LogUtils.logWarn(owner, getClass(), "getSecuritySubProfile", "WTF mode: More than one SecuritySubprofile found for the given user: " + usr.getURI());
			ssp = (SecuritySubprofile) ((List)o).get(0);
		} else {
			LogUtils.logError(owner, getClass(), "getSecuritySubProfile", "No SecuritySubprofile found for the given user: " + usr.getURI());
			return null;
		}
		return ssp;
	}
	
	private void updateProperty(Resource r, String prop) {
		
		String serialization = serializer.getObject().serialize(r.getProperty(prop));
		
		String[] split = CHeQuerrier.splitPrefixes(serialization);
		
		String prefixes = split[0];
		String serialValue = split[1];
		CHeQuerrier query = new CHeQuerrier(owner);
		query.query(CHeQuerrier.getQuery(CHeQuerrier.getResource("updateProperty.sparql"), new String[]{prefixes,r.getURI(),prop, serialValue}));
		
	}
	
}

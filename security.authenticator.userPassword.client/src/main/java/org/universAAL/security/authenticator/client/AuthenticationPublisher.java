/*******************************************************************************
 * Copyright 2013 Universidad Politécnica de Madrid
 * Copyright 2013 Fraunhofer-Gesellschaft - Institute for Computer Graphics Research
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

package org.universAAL.security.authenticator.client;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.context.ContextEvent;
import org.universAAL.middleware.context.ContextEventPattern;
import org.universAAL.middleware.context.ContextPublisher;
import org.universAAL.middleware.context.owl.ContextProvider;
import org.universAAL.middleware.context.owl.ContextProviderType;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.ontology.phThing.Device;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.SecurityOntology;

/**
 * This class should be used when the Authentication is successful, to allow the
 * Session Manager to uplift the authentication to a Session.
 *
 * @author amedrano
 *
 */
public class AuthenticationPublisher extends ContextPublisher {

	/**
	 * @param context
	 * @param providerInfo
	 */
	public AuthenticationPublisher(ModuleContext context) {
		super(context, getProvider());
	}

	public static ContextProvider getProvider() {
		// creates a context provider for CompetitionDevices
		ContextProvider cprovider;
		cprovider = new ContextProvider();
		cprovider.setProvidedEvents(getPattern());
		cprovider.setType(ContextProviderType.gauge);
		return cprovider;
	}

	public static ContextEventPattern[] getPattern() {
		ContextEventPattern[] patterns = new ContextEventPattern[2];
		ContextEventPattern cep = new ContextEventPattern();
		cep.addRestriction(MergedRestriction.getAllValuesRestriction(ContextEvent.PROP_RDF_OBJECT, Device.MY_URI));
		cep.addRestriction(MergedRestriction.getAllValuesRestriction(ContextEvent.PROP_RDF_SUBJECT, User.MY_URI));
		cep.addRestriction(MergedRestriction.getFixedValueRestriction(ContextEvent.PROP_RDF_PREDICATE,
				SecurityOntology.PROP_AUTHENTICATED));
		patterns[0] = cep;
		cep = new ContextEventPattern();
		cep.addRestriction(MergedRestriction.getAllValuesRestriction(ContextEvent.PROP_RDF_OBJECT, Device.MY_URI));
		cep.addRestriction(MergedRestriction.getAllValuesRestriction(ContextEvent.PROP_RDF_SUBJECT, User.MY_URI));
		cep.addRestriction(MergedRestriction.getFixedValueRestriction(ContextEvent.PROP_RDF_PREDICATE,
				SecurityOntology.PROP_REVOKED));
		patterns[1] = cep;
		return patterns;
	}

	/** {@ inheritDoc} */
	public void communicationChannelBroken() {

	}

	public void authenticate(User u, Device d) {
		u.changeProperty(SecurityOntology.PROP_AUTHENTICATED, d);
		publish(new ContextEvent(u, SecurityOntology.PROP_AUTHENTICATED));
	}

	public void deauthenticate(User u, Device d) {
		u.changeProperty(SecurityOntology.PROP_REVOKED, d);
		publish(new ContextEvent(u, SecurityOntology.PROP_REVOKED));
	}
}

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

package org.security.session.manager.context;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.context.ContextEvent;
import org.universAAL.middleware.context.ContextEventPattern;
import org.universAAL.middleware.context.ContextPublisher;
import org.universAAL.middleware.context.owl.ContextProvider;
import org.universAAL.middleware.context.owl.ContextProviderType;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.security.Session;

/**
 * @author amedrano
 *
 */
public class SessionPublisher extends ContextPublisher {

    /**
     * @param context
     * @param providerInfo
     */
    public SessionPublisher(ModuleContext context, ContextProvider providerInfo) {
	super(context, providerInfo);
    }
    
    public SessionPublisher(ModuleContext context){
	this(context, getProvider());
    }

    /**
     * @return
     */
    private static ContextProvider getProvider() {
	ContextProvider cp = new ContextProvider();
	ContextEventPattern cep = new ContextEventPattern();
	cep.addRestriction(MergedRestriction.getAllValuesRestrictionWithCardinality(ContextEvent.PROP_RDF_SUBJECT, User.MY_URI, 1, 1));
	cep.addRestriction(MergedRestriction.getFixedValueRestriction(ContextEvent.PROP_RDF_PREDICATE, SecurityOntology.PROP_SESSION));
	cep.addRestriction(MergedRestriction.getAllValuesRestrictionWithCardinality(ContextEvent.PROP_RDF_OBJECT, Session.MY_URI, 1, 1));
	cp.setProvidedEvents(new ContextEventPattern[]{cep});
	cp.setType(ContextProviderType.gauge);
	return cp;
    }

    /** {@ inheritDoc}	 */
    @Override
    public void communicationChannelBroken() {

    }

}

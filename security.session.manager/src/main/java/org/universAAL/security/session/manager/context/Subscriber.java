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

package org.universAAL.security.session.manager.context;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.context.ContextEvent;
import org.universAAL.middleware.context.ContextEventPattern;
import org.universAAL.middleware.context.ContextSubscriber;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.ontology.location.Location;
import org.universAAL.ontology.phThing.Device;
import org.universAAL.ontology.phThing.PhysicalThing;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.security.session.manager.SessionManager;

/**
 * @author amedrano
 *
 */
public class Subscriber extends ContextSubscriber {

	private SessionManager sm;

	private QueueProcessor processor = new QueueProcessor();

	/**
	 * 
	 */
	public Subscriber(ModuleContext mc, SessionManager sessionMngr) {
		super(mc, getPermSusbcriptions());
		sm = sessionMngr;
		new Thread(processor, "SessionManagerContextEventProcessor").start();
	}

	/**
	 * @return
	 */
	private static ContextEventPattern[] getPermSusbcriptions() {
		ContextEventPattern[] patterns = new ContextEventPattern[3];
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
		cep = new ContextEventPattern();
		cep.addRestriction(MergedRestriction.getAllValuesRestriction(ContextEvent.PROP_RDF_OBJECT, Location.MY_URI));
		cep.addRestriction(MergedRestriction.getAllValuesRestriction(ContextEvent.PROP_RDF_SUBJECT, User.MY_URI));
		cep.addRestriction(MergedRestriction.getFixedValueRestriction(ContextEvent.PROP_RDF_PREDICATE,
				PhysicalThing.PROP_PHYSICAL_LOCATION));
		patterns[2] = cep;
		return patterns;
	}

	/** {@ inheritDoc} */
	public void communicationChannelBroken() {

	}

	/** {@ inheritDoc} */
	public void handleContextEvent(ContextEvent event) {
		if (event == null)
			return;
		processor.queue.add(event);
	}

	/** {@ inheritDoc} */
	public void close() {
		processor.stop();
		super.close();
	}

	private class QueueProcessor implements Runnable {

		private LinkedBlockingQueue<ContextEvent> queue = new LinkedBlockingQueue<ContextEvent>();
		private boolean run = true;

		/** {@ inheritDoc} */
		public void run() {
			while (run || !queue.isEmpty()) {
				try {
					ContextEvent next = queue.poll(5, TimeUnit.MINUTES);
					if (next != null) {
						process(next);
					}
				} catch (InterruptedException e) {
				}
			}
		}

		void process(ContextEvent event) {
			try {
				if (event.getRDFPredicate().equals(SecurityOntology.PROP_AUTHENTICATED)) {
					sm.userAuthenticatedTo((User) event.getRDFSubject(), (Device) event.getRDFObject());
				}
				if (event.getRDFPredicate().equals(SecurityOntology.PROP_REVOKED)) {
					sm.userDeauthenticatedFrom((User) event.getRDFSubject(), (Device) event.getRDFObject());
				}
				if (event.getRDFPredicate().equals(PhysicalThing.PROP_PHYSICAL_LOCATION)) {
					sm.userLocationChange((User) event.getRDFSubject(), (Location) event.getRDFObject());
				}
			} catch (Exception e) {
				LogUtils.logWarn(owner, getClass(), "handleContextEvent",
						new String[] { "Something whent wrong interpreting the event, probably the casting. " }, e);
			}
		}

		void stop() {
			run = false;
		}
	}
}

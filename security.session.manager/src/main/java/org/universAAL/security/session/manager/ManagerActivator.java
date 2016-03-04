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
package org.universAAL.security.session.manager;

import org.universAAL.middleware.container.ModuleActivator;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.security.session.manager.context.SessionPublisher;
import org.universAAL.security.session.manager.context.SituationMonitor;
import org.universAAL.security.session.manager.context.Subscriber;
import org.universAAL.security.session.manager.helpers.CHeQuery;
import org.universAAL.security.session.manager.impl.SessionManagerImpl;
import org.universAAL.security.session.manager.impl.SituationMonitorImpl;
import org.universAAL.security.session.manager.service.SCallee;
import org.universAAL.security.session.manager.service.SessionManagerService;

public class ManagerActivator implements ModuleActivator {

    ModuleContext context;

    SessionManager sessionManager;

    private Subscriber subscriber;

    private SCallee scallee;

    private SessionPublisher publisher;

    private SituationMonitor monitor;

    public void start(ModuleContext ctxt) throws Exception {
	context = ctxt;
	LogUtils.logDebug(context, getClass(), "start", "Starting.");
	/*
	 * uAAL stuff
	 */
	LogUtils.logDebug(context, getClass(), "start", "Starting Publisher.");
	publisher = new SessionPublisher(context);

	LogUtils.logDebug(context, getClass(), "start",
		"Starting Situation Monitor.");
	monitor = new SituationMonitorImpl(context);

	// Initialize sessionManager.
	LogUtils.logDebug(context, getClass(), "start",
		"Starting Session Manager.");
	sessionManager = new SessionManagerImpl(context, monitor, publisher);

	LogUtils.logDebug(context, getClass(), "start", "Starting Susbscriber.");
	subscriber = new Subscriber(context, sessionManager);

	LogUtils.logDebug(context, getClass(), "start", "Adding services.");
	scallee = new SCallee(context,
		SessionManagerService.initialize(context), sessionManager);
	LogUtils.logDebug(context, getClass(), "start", "Started.");
    }

    public void stop(ModuleContext ctxt) throws Exception {
	LogUtils.logDebug(context, getClass(), "stop", "Stopping.");
	/*
	 * close uAAL stuff
	 */
	if (publisher != null) {
	    publisher.close();
	    LogUtils.logDebug(context, getClass(), "start", "Stopping.");
	    publisher = null;
	}
	if (monitor != null) {
	    monitor.close();
	    monitor = null;
	}
	if (subscriber != null) {
	    subscriber.close();
	    subscriber = null;
	}
	if (scallee != null) {
	    scallee.close();
	    scallee = null;
	}

	CHeQuery.close();

	LogUtils.logDebug(context, getClass(), "stop", "Stopped.");
    }
}

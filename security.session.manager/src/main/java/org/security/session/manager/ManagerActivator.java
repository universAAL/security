package org.security.session.manager;

import org.security.session.manager.context.SessionPublisher;
import org.security.session.manager.context.SituationMonitor;
import org.security.session.manager.context.Subscriber;
import org.security.session.manager.impl.SessionManagerImpl;
import org.security.session.manager.service.SCallee;
import org.security.session.manager.service.SessionManagerService;
import org.universAAL.middleware.container.ModuleActivator;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;

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

		LogUtils.logDebug(context, getClass(), "start", "Starting Situation Monitor.");
		//monitor ;
		
		//Initialize sessionManager.
		LogUtils.logDebug(context, getClass(), "start", "Starting Session Manager.");
		sessionManager = new SessionManagerImpl(context, monitor, publisher);
		
		LogUtils.logDebug(context, getClass(), "start", "Starting Susbscriber.");
		subscriber = new Subscriber(context, sessionManager);
		

		LogUtils.logDebug(context, getClass(), "start", "Adding services.");
		scallee = new SCallee(context, SessionManagerService.initialize(context), sessionManager);
		LogUtils.logDebug(context, getClass(), "start", "Started.");
	}


	public void stop(ModuleContext ctxt) throws Exception {
		LogUtils.logDebug(context, getClass(), "stop", "Stopping.");
		/*
		 * close uAAL stuff
		 */
		if (publisher != null){
		    publisher.close();
			LogUtils.logDebug(context, getClass(), "start", "Stopping.");
		    publisher = null;
		}
		if (monitor != null){
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
		
		LogUtils.logDebug(context, getClass(), "stop", "Stopped.");

	}

}

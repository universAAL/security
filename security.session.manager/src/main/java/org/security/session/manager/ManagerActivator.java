package org.security.session.manager;

import org.security.session.manager.context.SessionPublisher;
import org.security.session.manager.context.Subscriber;
import org.security.session.manager.impl.SituationCaller;
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

	private SituationCaller scaller;
	
	public void start(ModuleContext ctxt) throws Exception {	
		context = ctxt;
		LogUtils.logDebug(context, getClass(), "start", "Starting.");
		/*
		 * uAAL stuff
		 */
		publisher = new SessionPublisher(context);
		scaller = new SituationCaller(context);
		
		//TODO Initialize sessionManager.
		subscriber = new Subscriber(context, sessionManager);
		scallee = new SCallee(context, SessionManagerService.initialize(context), sessionManager);
		LogUtils.logDebug(context, getClass(), "start", "Started.");
	}


	public void stop(ModuleContext ctxt) throws Exception {
		LogUtils.logDebug(context, getClass(), "start", "Stopping.");
		/*
		 * close uAAL stuff
		 */
		if (publisher != null){
		    publisher.close();
		    publisher = null;
		}
		if (scaller != null){
		    scaller.close();
		    scaller = null;
		}
		if (subscriber != null) {
		    subscriber.close();
		    subscriber = null;
		}
		if (scallee != null) {
		    scallee.close();
		    scallee = null;
		}
		
		LogUtils.logDebug(context, getClass(), "start", "Stopped.");

	}

}

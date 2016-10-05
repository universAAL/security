package org.universAAL.security;

import org.universAAL.middleware.container.ModuleActivator;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.security.access_checkers.DelegationAccessChecker;

public class DelegationActivator implements ModuleActivator {

	static ModuleContext context;
	
	public void start(ModuleContext ctxt) throws Exception {	
		context = ctxt;
		LogUtils.logDebug(context, getClass(), "start", "Starting.");
		/*
		 * uAAL stuff
		 */
		//Add authorisation modification
		AuthorisatorCallee.registerChecker(new DelegationAccessChecker());
		
		LogUtils.logDebug(context, getClass(), "start", "Started.");
	}


	public void stop(ModuleContext ctxt) throws Exception {
		LogUtils.logDebug(context, getClass(), "stop", "Stopping.");
		/*
		 * close uAAL stuff
		 */
		AuthorisatorCallee.unregisterChecker(DelegationAccessChecker.class);
		
		LogUtils.logDebug(context, getClass(), "stop", "Stopped.");

	}

}

package org.universAAL.security.authorisator.delegation;

import org.universAAL.middleware.container.ModuleActivator;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.security.authorisator.AuthorisatorCallee;
import org.universAAL.security.authorisator.access_checkers.DelegationAccessChecker;

public class DelegationActivator implements ModuleActivator {

	static ModuleContext context;
	private DelegationServieCallee callee;
	
	public void start(ModuleContext ctxt) throws Exception {	
		context = ctxt;
		LogUtils.logDebug(context, getClass(), "start", "Starting.");
		/*
		 * uAAL stuff
		 */
		//Add authorisation modification
		AuthorisatorCallee.registerChecker(new DelegationAccessChecker());
		DelegationService.initialize(context);
		callee = new DelegationServieCallee(context, DelegationService.profs); 
		LogUtils.logDebug(context, getClass(), "start", "Started.");
	}


	public void stop(ModuleContext ctxt) throws Exception {
		LogUtils.logDebug(context, getClass(), "stop", "Stopping.");
		/*
		 * close uAAL stuff
		 */
		AuthorisatorCallee.unregisterChecker(DelegationAccessChecker.class);
		callee.close();
		LogUtils.logDebug(context, getClass(), "stop", "Stopped.");

	}

}

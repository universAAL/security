package org.universAAL.security.anonymization;

import org.universAAL.middleware.container.ModuleActivator;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;

public class ProjectActivator implements ModuleActivator {

	static ModuleContext context;
	private AnonServiceCallee callee;
	
	public void start(ModuleContext ctxt) throws Exception {	
		context = ctxt;
		LogUtils.logDebug(context, getClass(), "start", "Starting.");
		/*
		 * uAAL stuff
		 */
		AnonServiceProfile.initialize(context);
		callee = new AnonServiceCallee(context, AnonServiceProfile.profs);
		LogUtils.logDebug(context, getClass(), "start", "Started.");
	}


	public void stop(ModuleContext ctxt) throws Exception {
		LogUtils.logDebug(context, getClass(), "stop", "Stopping.");
		/*
		 * close uAAL stuff
		 */
		callee.close();
		LogUtils.logDebug(context, getClass(), "stop", "Stopped.");

	}

}

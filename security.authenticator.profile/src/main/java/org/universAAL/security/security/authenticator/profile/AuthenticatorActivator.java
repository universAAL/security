package org.universAAL.security.security.authenticator.profile;

import org.universAAL.middleware.container.ModuleActivator;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;

public class AuthenticatorActivator implements ModuleActivator {

    static ModuleContext context;
    private UserPasswordCallee callee;

    /** {@ inheritDoc} */
    public void start(ModuleContext mc) throws Exception {
	context = mc;
	LogUtils.logDebug(context, getClass(), "start", "Starting.");
	/*
	 * uAAL stuff
	 */
	UserPasswordProfileService.initialize(context);
	callee = new UserPasswordCallee(context);
	LogUtils.logDebug(context, getClass(), "start", "Started.");
    }

    /** {@ inheritDoc} */
    public void stop(ModuleContext mc) throws Exception {
	callee.close();
    }
}

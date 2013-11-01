package org.universAAL.security.security.authenticator.profile;

import org.universAAL.middleware.container.ModuleActivator;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.SharedObjectListener;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.serialization.MessageContentSerializerEx;

public class AuthenticatorActivator implements ModuleActivator, SharedObjectListener {

    ModuleContext context;
    private UserPasswordCallee callee;
    private MessageContentSerializerEx serializer; 

    /** {@ inheritDoc} */
    public void start(ModuleContext mc) throws Exception {
	context = mc;
	LogUtils.logDebug(context, getClass(), "start", "Starting.");
	/*
	 * uAAL stuff
	 */
	Object[] obj = context.getContainer()
		.fetchSharedObject(context, 
			new Object[] { MessageContentSerializerEx.class.getName() }, this);
	if (obj.length > 0){
	    sharedObjectAdded(obj[0], null);
	}
	
	UserPasswordProfileService.initialize(context);
	callee = new UserPasswordCallee(this);
	LogUtils.logDebug(context, getClass(), "start", "Started.");
    }

    /** {@ inheritDoc} */
    public void stop(ModuleContext mc) throws Exception {
	callee.close();
    }

    /** {@ inheritDoc}	 */
    public synchronized void sharedObjectAdded(Object sharedObj, Object removeHook) {
	serializer = (MessageContentSerializerEx) sharedObj;
	this.notifyAll();
    }

    /** {@ inheritDoc}	 */
    public synchronized void sharedObjectRemoved(Object removeHook) {
	if (removeHook.equals(serializer)){
	    serializer = null;
	}
    }
    
    public synchronized MessageContentSerializerEx getSerializer(){
	while (serializer == null){
	    try {
		this.wait();
	    } catch (InterruptedException e) {}
	}
	return serializer; 
    }

}

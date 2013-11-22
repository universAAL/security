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
	if (sharedObj instanceof MessageContentSerializerEx) {
	    serializer = (MessageContentSerializerEx) sharedObj;
	    this.notifyAll();
	}
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

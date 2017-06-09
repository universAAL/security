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
package org.universAAL.security.session.manager.helpers;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.SharedObjectListener;
import org.universAAL.middleware.serialization.MessageContentSerializerEx;

public class SerializerGetter implements SharedObjectListener {

	ModuleContext context;
	private MessageContentSerializerEx serializer;

	/**
	 * 
	 */
	public SerializerGetter(ModuleContext mc) throws Exception {
		context = mc;
		/*
		 * uAAL stuff
		 */
		Object[] obj = context.getContainer().fetchSharedObject(context,
				new Object[] { MessageContentSerializerEx.class.getName() }, this);
		if (obj.length > 0) {
			sharedObjectAdded(obj[0], null);
		}
	}

	/** {@ inheritDoc} */
	public synchronized void sharedObjectAdded(Object sharedObj, Object removeHook) {
		serializer = (MessageContentSerializerEx) sharedObj;
		this.notifyAll();
	}

	/** {@ inheritDoc} */
	public synchronized void sharedObjectRemoved(Object removeHook) {
		if (removeHook.equals(serializer)) {
			serializer = null;
		}
	}

	public synchronized MessageContentSerializerEx getSerializer() {
		while (serializer == null) {
			try {
				this.wait();
			} catch (InterruptedException e) {
			}
		}
		return serializer;
	}

}

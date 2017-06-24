/*******************************************************************************
 * Copyright 2016 Universidad Politécnica de Madrid UPM
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
package org.universAAL.security.cryptographic.services;

import org.universAAL.middleware.container.ModuleActivator;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.serialization.MessageContentSerializer;
import org.universAAL.utilities.ioc.dependencies.impl.PassiveDependencyProxy;

public class ProjectActivator implements ModuleActivator {

	public static ModuleContext context;
	private DigestServiceCallee digestCallee;
	private EncryptionServiceCallee encrypCallee;
	private SignVerifyCallee signCallee;
	private MultiDestinationCallee mderCallee;
	static PassiveDependencyProxy<MessageContentSerializer> serializer;

	public void start(ModuleContext ctxt) throws Exception {
		context = ctxt;
		LogUtils.logDebug(context, getClass(), "start", "Starting.");
		/*
		 * universAAL stuff
		 */
		serializer = new PassiveDependencyProxy<MessageContentSerializer>(context,
				new Object[] { MessageContentSerializer.class.getName() });

		DigestServiceProfiles.initialize(context);
		EncryptionServiceProfiles.initialize(context);
		SignVerifyProfiles.initialize(context);
		MultiDestinationProfiles.initialize(context);
		digestCallee = new DigestServiceCallee(context, DigestServiceProfiles.profs);
		encrypCallee = new EncryptionServiceCallee(context, EncryptionServiceProfiles.profs);
		signCallee = new SignVerifyCallee(context, SignVerifyProfiles.profs);
		mderCallee = new MultiDestinationCallee(context, MultiDestinationProfiles.profs);

		LogUtils.logDebug(context, getClass(), "start", "Started.");
	}

	public void stop(ModuleContext ctxt) throws Exception {
		LogUtils.logDebug(context, getClass(), "stop", "Stopping.");
		/*
		 * close universAAL stuff
		 */
		digestCallee.close();
		encrypCallee.close();
		signCallee.close();
		LogUtils.logDebug(context, getClass(), "stop", "Stopped.");

	}

}

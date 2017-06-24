/*
	Copyright 2008-2015 ITACA-TSB, http://www.tsb.upv.es
	Instituto Tecnologico de Aplicaciones de Comunicacion
	Avanzadas - Grupo Tecnologias para la Salud y el
	Bienestar (TSB)

	See the NOTICE file distributed with this work for additional
	information regarding copyright ownership

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	  http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
 */
package org.universAAL.security.authorisator.dummyCHe;

import java.util.List;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.context.owl.ContextProvider;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.ServiceCall;
import org.universAAL.middleware.service.ServiceCallee;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.process.ProcessOutput;

/**
 * The CHe service callee receives all service calls issued to the CHe through
 * the service bus.
 *
 * @author <a href="mailto:alfiva@itaca.upv.es">Alvaro Fides Valero</a>
 *
 */
public class ContextHistoryCallee extends ServiceCallee {
	private static final ServiceResponse FAILURE = new ServiceResponse(CallStatus.serviceSpecificFailure);


	/**
	 * Main constructor.
	 *
	 * @param context
	 *            The universAAL module context
	 * @param dbstore
	 *            The store
	 */
	public ContextHistoryCallee(ModuleContext context) {
		super(context, ContextHistoryServices.PROFILES);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.universAAL.middleware.service.ServiceCallee#
	 * communicationChannelBroken ()
	 */
	public void communicationChannelBroken() {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.universAAL.middleware.service.ServiceCallee#handleCall(org.universAAL
	 * .middleware.service.ServiceCall)
	 */
	public ServiceResponse handleCall(ServiceCall call) {
		if (call == null) {
			FAILURE.addOutput(new ProcessOutput(ServiceResponse.PROP_SERVICE_SPECIFIC_ERROR, "Corrupt call"));
			return FAILURE;
		}
		String operation = call.getProcessURI();
		if (operation == null) {
			FAILURE.addOutput(new ProcessOutput(ServiceResponse.PROP_SERVICE_SPECIFIC_ERROR, "Corrupt call"));
			return FAILURE;
		}
		List scopeList = call.getScopes();
		String[] scopeArray = (String[]) scopeList.toArray(new String[0]);
		if (operation.startsWith(ContextHistoryServices.SERVICE_DO_SPARQL_QUERY)) {
			Object input = call.getInputValue(ContextHistoryServices.INPUT_QUERY);
			if (input == null) {
				FAILURE.addOutput(new ProcessOutput(ServiceResponse.PROP_SERVICE_SPECIFIC_ERROR, "Invalid input"));
				return FAILURE;
			}
			return execSPARQLQuery((String) input, scopeArray);
		}
			String sub, typ, pre;
			Object obj;
			Integer con;
			Long exp, tst;
			ContextProvider cop;

		FAILURE.addOutput(new ProcessOutput(ServiceResponse.PROP_SERVICE_SPECIFIC_ERROR, "Invalid call"));
		return FAILURE;
	}

	/**
	 * Perform SPARQL query.
	 *
	 * @param input
	 *            The query
	 * @param scopeArray
	 * @return Response
	 */
	private ServiceResponse execSPARQLQuery(String input, String[] scopeArray) {
		try {
//			String results = db.queryBySPARQL(input, scopeArray);
			System.out.println(input);
			ServiceResponse response = new ServiceResponse(CallStatus.succeeded);
			response.addOutput(new ProcessOutput(ContextHistoryServices.OUTPUT_RESULT, "true"));
			return response;
		} catch (Exception e) {
			FAILURE.addOutput(
					new ProcessOutput(ServiceResponse.PROP_SERVICE_SPECIFIC_ERROR, "Error executing specific SPARQL"));
			return FAILURE;
		}
	}

}

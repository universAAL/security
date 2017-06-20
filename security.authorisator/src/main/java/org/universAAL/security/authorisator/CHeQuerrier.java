/*******************************************************************************
 * Copyright 2014 Universidad Politécnica de Madrid UPM
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
package org.universAAL.security.authorisator;

import java.io.InputStream;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

import org.universAAL.ioc.dependencies.DependencyProxy;
import org.universAAL.ioc.dependencies.impl.PassiveDependencyProxy;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.middleware.rdf.PropertyPath;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.serialization.MessageContentSerializer;
import org.universAAL.middleware.serialization.MessageContentSerializerEx;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.process.ProcessOutput;
import org.universAAL.ontology.che.ContextHistoryOntology;
import org.universAAL.ontology.che.ContextHistoryService;

/**
 * @author amedrano
 * 
 */
public class CHeQuerrier {

	private static final String UTF_8 = "utf-8";
	private static final String OUTPUT_RESULT_STRING = ContextHistoryOntology.NAMESPACE
			+ "outputfromCHE";

	private ModuleContext owner;
	private DependencyProxy<MessageContentSerializer> serial;

	public CHeQuerrier(ModuleContext mc) {
		this.owner = mc;
		serial = new PassiveDependencyProxy<MessageContentSerializer>(owner,
				new Object[] { MessageContentSerializer.class.getName() });
	}

	private String gURI() {
		return "http://authorisator.security.universaal.org/CHeCall#"
				+ UUID.randomUUID();
	}

	public String unserialisedQuery(String query) {
		ServiceRequest getQuery = new ServiceRequest(gURI(),
				new ContextHistoryService(null), null);

		MergedRestriction r = MergedRestriction.getFixedValueRestriction(
				ContextHistoryService.PROP_PROCESSES, query);

		getQuery.getRequestedService().addInstanceLevelRestriction(r,
				new String[] { ContextHistoryService.PROP_PROCESSES });
		getQuery.addSimpleOutputBinding(
				new ProcessOutput(OUTPUT_RESULT_STRING), new PropertyPath(null,
						true,
						new String[] { ContextHistoryService.PROP_RETURNS })
						.getThePath());
		ServiceCaller sc = new DefaultServiceCaller(owner);
		ServiceResponse sr = sc.call(getQuery);
		sc.close();
		if (!sr.getCallStatus().equals(CallStatus.succeeded)) {
			throw new RuntimeException("unable to query. Query:\n" + query
					+ "\nReturned:\n" + getSerializer().serialize(sr));
		}
		List res = sr.getOutput(OUTPUT_RESULT_STRING);
		if (res != null && res.size() > 0 && res.get(0) instanceof String) {
			return (String) res.get(0);
		}
		return null;
	}

	public Object query(String query) {
		try {
			Object res = getSerializer().deserialize(unserialisedQuery(query));
			return res;
		} catch (Exception e) {
			LogUtils.logError(owner, getClass(), "query",
					new String[] { "Error Deserializing, returning null." }, e);
			return null;
		}
	}

	private MessageContentSerializerEx getSerializer() {
		return (MessageContentSerializerEx) serial.getObject();
	}

	public static InputStream getResource(String Rfile) {
		return CHeQuerrier.class.getClassLoader().getResourceAsStream(Rfile);
	}

	public static String getQuery(InputStream file, String[] params) {
		String query = "";
		try {
			query = new Scanner(file, UTF_8).useDelimiter("\\Z").next();
			file.close();
		} catch (Exception e) {
			/*
			 * either: - empty file - non existent file - Scanner failture...
			 * Nothing to do here
			 */
		}
		for (int i = 0; i < params.length; i++) {
			query = query.replace("$" + Integer.toString(i + 1), params[i]);
		}
		return query;
	}

	/**
	 * Splits a Turtle serialized string into prefixes and content, so it can be
	 * used inside SPARQL queries.
	 * 
	 * @param serialized
	 *            The turtle string
	 * @return An array of length 2. The first item [0] is the string with the
	 *         prefixes, and the second [1] is the string with the triples
	 *         content
	 */
	public static String[] splitPrefixes(String serialized) {
		// Remove Data types, specially XMLLiterals
		String clean = serialized.replaceAll("\"[^\"]*?\"", "");
		int lastprefix = 0, lastprefixdot = 0, lastprefixuri = 0;
		lastprefix = clean.toLowerCase().lastIndexOf("@prefix");
		if (lastprefix >= 0) {
			lastprefixuri = clean.substring(lastprefix).indexOf(">");
			lastprefixdot = clean.substring(lastprefix + lastprefixuri)
					.indexOf(".");
		}
		String[] result = new String[2];
		result[0] = clean
				.substring(0, lastprefixuri + lastprefixdot + lastprefix + 1)
				.replace("@", " ").replace(">.", "> ").replace(" .", " ")
				.replace(". ", " ");
		result[1] = serialized.substring(lastprefixuri + lastprefixdot
				+ lastprefix + 1);
		return result;
	}

	public Resource getFullResourceGraph(String uri) {
		String query = "prefix : <urn:foo:test>\n" + "CONSTRUCT { ?s ?p ?o }\n"
				+ "WHERE { <" + uri + "> (:a|!:a)* ?s . ?s ?p ?o . }";

		Object o = getSerializer().deserialize(unserialisedQuery(query), uri);
		Resource r = (Resource) o;
		LogUtils.logDebug(owner, getClass(), "getFullResourceGraph",
				"result:\n" + getSerializer().serialize(r));
		return r;
	}
}

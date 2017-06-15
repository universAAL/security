/*
	Copyright 2008-2014 ITACA-TSB, http://www.tsb.upv.es
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

import org.universAAL.container.JUnit.JUnitModuleContext;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.owl.SimpleOntology;
import org.universAAL.middleware.rdf.PropertyPath;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.rdf.ResourceFactory;
import org.universAAL.middleware.rdf.TypeMapper;
import org.universAAL.middleware.service.owls.process.ProcessInput;
import org.universAAL.middleware.service.owls.process.ProcessOutput;
import org.universAAL.middleware.service.owls.profile.ServiceProfile;
import org.universAAL.ontology.che.ContextHistoryService;

/**
 * Here are described the provided services that are registered by the CHe in
 * the service bus.
 * 
 * @author <a href="mailto:alfiva@itaca.upv.es">Alvaro Fides Valero</a>
 * 
 */
public class ContextHistoryServices extends ContextHistoryService {

	public static final String CHE_NAMESPACE = "http://ontology.universAAL.org/CHE.owl#";
	public static final String MY_URI = CHE_NAMESPACE + "CHeService";

	static final String SERVICE_DO_SPARQL_QUERY = CHE_NAMESPACE + "doSparqlQuery";

	static final String INPUT_QUERY = CHE_NAMESPACE + "sparqlQuery";

	static final String OUTPUT_RESULT = CHE_NAMESPACE + "sparqlResult";

	static final ServiceProfile[] PROFILES = new ServiceProfile[1];

	static {
		OntologyManagement.getInstance().register(new JUnitModuleContext(),
				new SimpleOntology(MY_URI, ContextHistoryService.MY_URI, new ResourceFactory() {
					public Resource createInstance(String classURI, String instanceURI, int factoryIndex) {
						return new ContextHistoryServices(instanceURI);
					}
				}));


		ProcessInput queryInput = new ProcessInput(INPUT_QUERY);
		queryInput.setParameterType(TypeMapper.getDatatypeURI(String.class));
		queryInput.setCardinality(1, 1);

		MergedRestriction queryr = MergedRestriction.getFixedValueRestriction(ContextHistoryService.PROP_PROCESSES,
				queryInput.asVariableReference());


		ProcessOutput resultoutput = new ProcessOutput(OUTPUT_RESULT);
		resultoutput.setParameterType(TypeMapper.getDatatypeURI(String.class));
		resultoutput.setCardinality(1, 1);

		PropertyPath managesPath = new PropertyPath(null, false, new String[] { ContextHistoryService.PROP_MANAGES });

		PropertyPath returnsPath = new PropertyPath(null, true, new String[] { ContextHistoryService.PROP_RETURNS });

		// SPARQL_QUERY
		ContextHistoryServices doSPARQL = new ContextHistoryServices(SERVICE_DO_SPARQL_QUERY);
		PROFILES[0] = doSPARQL.getProfile();
		PROFILES[0].addInput(queryInput);
		doSPARQL.addInstanceLevelRestriction(queryr, new String[] { ContextHistoryService.PROP_PROCESSES });
		PROFILES[0].addOutput(resultoutput);
		PROFILES[0].addSimpleOutputBinding(resultoutput, returnsPath.getThePath());

	}

	/**
	 * Main constructor.
	 * 
	 * @param uri
	 *            URI
	 */
	public ContextHistoryServices(String uri) {
		super(uri);
	}

	/**
	 * Default constructor.
	 */
	public ContextHistoryServices() {
		super();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.universAAL.ontology.che.ContextHistoryService#getClassURI()
	 */
	public String getClassURI() {
		return MY_URI;
	}

}

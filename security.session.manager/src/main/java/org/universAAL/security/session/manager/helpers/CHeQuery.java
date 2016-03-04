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

import java.io.InputStream;
import java.util.List;
import java.util.Scanner;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.owl.MergedRestriction;
import org.universAAL.middleware.rdf.PropertyPath;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.process.ProcessOutput;
import org.universAAL.ontology.che.ContextHistoryService;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.security.session.manager.impl.SituationMonitorImpl;

/**
 * @author amedrano
 *
 */
public class CHeQuery {
    
    private static final String UTF_8 = "utf-8";
    private static final String OUTPUT_RESULT_STRING = SecurityOntology.NAMESPACE
	    + "outputfromCHE";
    private ModuleContext owner;
    private static ServiceCaller sc = null;
    
    /**
     * 
     */
    public CHeQuery(ModuleContext mc) {
	owner = mc;
	if (sc == null) {
	    sc = new DefaultServiceCaller(owner);
	    sc.setLabel("Security Session Manager CHE Query");
	}
    }
    
    public static void close() {
	if (sc == null) {
	    sc.close();
	    sc = null;
	}
    }

    public Object query(String queryFile, String[] params){
  	String q = getQuery(queryFile, params);
  	ServiceRequest getQuery = new ServiceRequest(
  		new ContextHistoryService(null), null);

  	MergedRestriction r = MergedRestriction.getFixedValueRestriction(
  		ContextHistoryService.PROP_PROCESSES, q);

  	getQuery.getRequestedService().addInstanceLevelRestriction(r,
  		new String[] { ContextHistoryService.PROP_PROCESSES });
  	getQuery.addSimpleOutputBinding(
  		new ProcessOutput(OUTPUT_RESULT_STRING), new PropertyPath(null,
  			true,
  			new String[] { ContextHistoryService.PROP_RETURNS })
  			.getThePath());
  	ServiceResponse sr = sc.call(getQuery);
  	List res = sr.getOutput(OUTPUT_RESULT_STRING, true);
  	if (res.size() >0 && res.get(0) instanceof String){
  	    try {
		return new SerializerGetter(owner).getSerializer().deserialize((String) res.get(0));
	    } catch (Exception e) {
		LogUtils.logError(owner, getClass(), "query", new String[]{"Error"}, e);
	    }
  	}
  	return null;
      }

 

    public static String getQuery(String queryFile, String[] params){
  	String query = "";
  	try {
  	    	InputStream file = SituationMonitorImpl.class.getClassLoader().getResourceAsStream(queryFile);
  		query = new Scanner(file,UTF_8).useDelimiter("\\Z").next();
  		file.close();
  	} catch (Exception e){
  		/*
  		 *  either:
  		 *  	- empty file
  		 *  	- non existent file
  		 *  	- Scanner failture...
  		 *  Nothing to do here
  		 */
  	}
  	if (params != null) {
	    for (int i = 0; i < params.length; i++) {
		query = query.replace("$" + Integer.toString(i + 1), params[i]);
	    }
	}
	return query;
      }
}

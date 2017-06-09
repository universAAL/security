/*******************************************************************************
 * Copyright 2016 2011 Universidad Politécnica de Madrid
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

import junit.framework.TestCase;

import org.universAAL.container.JUnit.JUnitModuleContext;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.owl.DataRepOntology;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.owl.TypeExpression;
import org.universAAL.middleware.owl.TypeURI;
import org.universAAL.middleware.serialization.MessageContentSerializer;
import org.universAAL.middleware.serialization.turtle.TurtleSerializer;
import org.universAAL.ontology.cryptographic.CryptographicOntology;
import org.universAAL.ontology.location.LocationOntology;
import org.universAAL.ontology.phThing.PhThingOntology;
import org.universAAL.ontology.profile.ProfileOntology;
import org.universAAL.ontology.security.AccessRight;
import org.universAAL.ontology.security.AccessType;
import org.universAAL.ontology.security.DelegationForm;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.shape.ShapeOntology;
import org.universAAL.ontology.space.SpaceOntology;
import org.universAAL.ontology.vcard.VCardOntology;

/**
 * @author amedrano
 *
 */
public class TestMatchMaking extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
		ModuleContext mc = new JUnitModuleContext();
		OntologyManagement.getInstance().register(mc, new DataRepOntology());
		// OntologyManagement.getInstance().register(mc, new
		// ServiceBusOntology());
		// OntologyManagement.getInstance().register(mc, new UIBusOntology());
		OntologyManagement.getInstance().register(mc, new LocationOntology());
		// OntologyManagement.getInstance().register(mc, new SysinfoOntology());
		OntologyManagement.getInstance().register(mc, new ShapeOntology());
		OntologyManagement.getInstance().register(mc, new PhThingOntology());
		OntologyManagement.getInstance().register(mc, new SpaceOntology());
		OntologyManagement.getInstance().register(mc, new VCardOntology());
		OntologyManagement.getInstance().register(mc, new ProfileOntology());
		// OntologyManagement.getInstance().register(mc, new
		// MenuProfileOntology());
		OntologyManagement.getInstance().register(mc, new CryptographicOntology());
		OntologyManagement.getInstance().register(mc, new SecurityOntology());
	}

	public void testExecution() {
		MessageContentSerializer serializer = new TurtleSerializer();
		AccessRight ar = new AccessRight();// NAMESPACE+
											// "accessToAllDelegationForms");
		ar.addAccessType(AccessType.add);
		ar.addAccessType(AccessType.change);
		ar.addAccessType(AccessType.remove);
		ar.addAccessType(AccessType.read);
		ar.setAccessTo(new TypeURI(DelegationForm.MY_URI, false));

		DelegationForm asset = new DelegationForm();

		Object te = ar.getProperty(AccessRight.PROP_ACCESS_TO);
		// System.out.println("te of class" + te.getClass().getCanonicalName());
		// System.out.println("Checking Membership of:"
		// + serializer.serialize(asset) + "\nwith: " +
		// serializer.serialize(te));
		assertTrue(te instanceof TypeExpression && ((TypeExpression) te).hasMember(asset));
	}
}

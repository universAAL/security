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
package org.universAAL.security.anonymization;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import junit.framework.TestCase;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.JUnit.JUnitModuleContext;
import org.universAAL.middleware.owl.DataRepOntology;
import org.universAAL.middleware.owl.OntologyManagement;
import org.universAAL.middleware.rdf.Resource;
import org.universAAL.middleware.serialization.MessageContentSerializer;
import org.universAAL.middleware.serialization.turtle.TurtleSerializer;
import org.universAAL.middleware.service.owl.ServiceBusOntology;
import org.universAAL.ontology.cryptographic.CryptographicOntology;
import org.universAAL.ontology.location.LocationOntology;
import org.universAAL.ontology.phThing.PhThingOntology;
import org.universAAL.ontology.profile.ProfileOntology;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.shape.ShapeOntology;
import org.universAAL.ontology.space.SpaceOntology;
import org.universAAL.ontology.vcard.VCardOntology;
import org.universAAL.security.anonymization.AnonServiceCallee;
import org.universAAL.utilities.ioc.dependencies.impl.PassiveDependencyProxy;

/**
 * @author amedrano
 *
 */
public class URIsTest extends TestCase {

	private static ModuleContext mc;
	private PassiveDependencyProxy<MessageContentSerializer> serializer;

	/** {@inheritDoc} */
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		mc = new JUnitModuleContext();
		mc.getContainer().shareObject(mc, new TurtleSerializer(),
				new Object[] { MessageContentSerializer.class.getName() });

		serializer = new PassiveDependencyProxy<MessageContentSerializer>(mc,
				new Object[] { MessageContentSerializer.class.getName() });

		OntologyManagement.getInstance().register(mc, new DataRepOntology());
		OntologyManagement.getInstance().register(mc, new ServiceBusOntology());
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

	public void testURIEncoding() throws UnsupportedEncodingException {

		Resource tr = RandomResourceGenerator.randomResource();

		String serialised = serializer.getObject().serialize(tr);
		String newURI = AnonServiceCallee.flatten2URI(serialised);

		// System.out.println(newURI);

		String deserialized = AnonServiceCallee.unflattenFromURI(newURI);
		// System.out.println(deserialized);
		Resource mder = (Resource) serializer.getObject().deserialize(deserialized);
		assertEquals(tr, mder);
	}

	public void testCopyWReplacedProperty() {
		Resource tr = RandomResourceGenerator.randomResource();
		String propname = "http://test.universAAL.org/Anon.owl#testproperty";
		String origVal = RandomResourceGenerator.randomText();
		tr.setProperty(propname, origVal);

		String newVal = RandomResourceGenerator.randomText();

		Resource r2 = AnonServiceCallee.copyWreplacedProperty(tr, origVal, newVal);

		assertEquals(newVal, r2.getProperty(propname));

	}

}

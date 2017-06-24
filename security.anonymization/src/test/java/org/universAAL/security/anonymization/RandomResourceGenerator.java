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
package org.universAAL.security.anonymization;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;

import org.universAAL.middleware.rdf.Resource;

/**
 * @author amedrano
 *
 */
public class RandomResourceGenerator {

	static private SecureRandom random = new SecureRandom();

	static private String NAMESPACE = "http://ontologies.universAAL.org/Test.owl#";

	static public String randomText() {
		return new BigInteger(130, random).toString(32);
	}

	static public int randomNumber(int minimum, int maximum) {
		return minimum + (int) (Math.random() * maximum);
	}

	static public Resource randomResource() {
		return genResource(5, 2, 10);
	}

	static public Resource genResource(int depth, int minprops, int maxprops) {
		Resource r = new Resource(NAMESPACE + randomText());
		int nprops = randomNumber(minprops, maxprops);
		for (int i = 0; i < nprops; i++) {
			int propType = randomNumber(0, 3);
			switch (propType) {
			case 0: // Integer
				r.setProperty(NAMESPACE + "propInt" + randomText(), new Integer(randomNumber(0, 1024)));
				break;
			case 1: // String
				r.setProperty(NAMESPACE + "propString" + randomText(), randomText());
				break;
			case 2:
			case 3: // another Resource
				if (depth > 0) {
					r.setProperty(NAMESPACE + "propRes" + randomText(), genResource(depth - 1, minprops, maxprops));
				}
				break;
			default:
				break;
			}
		}
		return r;
	}

	static boolean fullResourceEquals(Resource a, Resource b) {
		HashSet aSet = new HashSet(Collections.list(a.getPropertyURIs()));
		HashSet bSet = new HashSet(Collections.list(b.getPropertyURIs()));
		if (!aSet.equals(bSet)) {
			return false;
		}
		for (Object prop : aSet) {
			Object val = a.getProperty((String) prop);
			if (val instanceof Resource
					&& !fullResourceEquals((Resource) val, (Resource) b.getProperty((String) prop))) {
				return false;
			} else if (!val.equals(b.getProperty((String) prop))) {
				return false;
			}
		}

		return true;
	}

}

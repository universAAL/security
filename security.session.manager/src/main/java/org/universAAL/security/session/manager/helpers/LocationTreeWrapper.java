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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.universAAL.ontology.location.Location;

/**
 * Some Utility tools missing from the ontology. This class gives a utility
 * model of the {@link Location} tree represented by the {@link Location}
 * instances. It relies on the data they have, and creates no more information.
 * 
 * @author amedrano
 * 
 */
public class LocationTreeWrapper {

	protected Location loc;

	/**
	 * Constructor. Model the given Location.
	 * 
	 * @param l
	 *            the location to be extended.
	 */
	public LocationTreeWrapper(Location l) {
		loc = l;
	}

	/**
	 * @return The location linked to this element.
	 */
	public Location getLocation() {
		return loc;
	}

	/**
	 * Get all {@link Location#PROP_CONTAINS children} of the {@link Location}
	 * represented buy this node.
	 * 
	 * @return The children in {@link LocationTreeWrapper} form.
	 */
	public Set<LocationTreeWrapper> getChildren() {
		HashSet<LocationTreeWrapper> children = new HashSet<LocationTreeWrapper>();
		Object contains = loc.getProperty(Location.PROP_CONTAINS);
		if (contains instanceof Location) {
			children.add(new LocationTreeWrapper((Location) contains));
		}
		if (contains instanceof List<?>) {
			for (Object con : (List) contains) {
				if (con instanceof Location) {
					children.add(new LocationTreeWrapper((Location) con));
				}
			}
		}
		return children;
	}

	/**
	 * Get the {@link Location#PROP_IS_CONTAINED_IN parent} {@link Location} of
	 * the represented {@link Location} in {@link LocationTreeWrapper} form.
	 * 
	 * @return the Parent node, or null if no parent is defined.
	 */
	public LocationTreeWrapper getParent() {
		Object containedIn = loc.getProperty(Location.PROP_IS_CONTAINED_IN);
		if (containedIn != null && containedIn instanceof Location) {
			return new LocationTreeWrapper((Location) containedIn);
		}
		return null;
	}

	/**
	 * Get the most generic {@link Location} reachable from the {@link Location}
	 * represented.
	 * 
	 * @return the tree root.
	 */
	public LocationTreeWrapper getRoot() {
		if (isRoot()) {
			return this;
		} else {
			return getParent().getRoot();
		}
	}

	/**
	 * Check if there are no parents. If they are not any parents then this must
	 * be the root node of the {@link Location} tree.
	 * 
	 * @return
	 */
	public boolean isRoot() {
		return getParent() == null;
	}

	/** {@ inheritDoc} */
	public boolean equals(LocationTreeWrapper obj) {
		return loc.equals(obj.loc);
	}
}

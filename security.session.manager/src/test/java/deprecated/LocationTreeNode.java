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

package deprecated;

import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.universAAL.ontology.location.Location;

/**
 * @author amedrano
 *
 */
public class LocationTreeNode {

	Location loc;

	Set<LocationTreeNode> children;

	private LocationTreeNode parent;

	/**
	 * 
	 */
	public LocationTreeNode(Location l) {
		loc = l;
		Object contains = loc.getProperty(Location.PROP_CONTAINS);
		if (contains instanceof Location) {
			add((Location) contains);
		}
		if (contains instanceof List<?>) {
			for (Object con : (List) contains) {
				if (con instanceof Location) {
					add((Location) con);
				}
			}
		}
	}

	public void add(Location l) {
		if (l != loc && l != null) {
			LocationTreeNode nLTN = new LocationTreeNode(l);
			LocationTreeNode parent = search(nLTN.getLocationParent());
			if (parent != null) {
				nLTN.parent = parent;
				parent.children.add(nLTN);
			} else {
				nLTN.parent = this;
				children.add(nLTN);
			}
		}
	}

	public void add(LocationTreeNode ltn) {
		if (ltn != null && ltn.loc != loc) {
			LocationTreeNode addRoot = search(ltn.loc);
			if (addRoot != null) {
				for (LocationTreeNode cltn : ltn.children) {
					cltn.parent = addRoot;
					addRoot.children.add(cltn);
				}
			} else {
				addRoot = search(ltn.getLocationParent());
				if (addRoot != null) {
					ltn.parent = addRoot;
					addRoot.children.add(ltn);
				} else {
					ltn.parent = this;
					children.add(ltn);
				}
			}
		}
	}

	public LocationTreeNode search(Location l) {
		LocationTreeNode found = null;
		Iterator<LocationTreeNode> it = children.iterator();
		while (l != null && found == null && it.hasNext()) {
			found = it.next().search(l);
		}
		return found;
	}

	public LocationTreeNode getParent() {
		return parent;
	}

	public LocationTreeNode getRoot() {
		if (parent == null) {
			return this;
		} else {
			return parent.getRoot();
		}
	}

	public Location getLocationParent() {
		return (Location) loc.getProperty(Location.PROP_IS_CONTAINED_IN);
	}

	/** {@ inheritDoc} */
	public boolean equals(LocationTreeNode obj) {
		return loc.equals(obj.loc);
	}

}

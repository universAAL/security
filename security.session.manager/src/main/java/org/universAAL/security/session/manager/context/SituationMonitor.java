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

package org.universAAL.security.session.manager.context;

import java.util.List;

import org.universAAL.ontology.location.Location;
import org.universAAL.ontology.phThing.Device;

/**
 * Implementation will initialize status and monitor changes regarding
 * {@link Device}s and {@link Location}s; in order to keep internal status
 * synchronized with actual status.
 * 
 * @author amedrano
 * 
 */
public interface SituationMonitor {

	public Location locationOf(Device d);

	public Location getInternalStateOf(Location l);

	public Device getInternalStateOf(Device d);

	public List<Location> getAllAvailableLocations();

	public List<Device> devicesInLocation(Location loc);

	public void addListener(LocationChangeListener lcl);

	public void removeListener(LocationChangeListener lcl);

	public void close();
}

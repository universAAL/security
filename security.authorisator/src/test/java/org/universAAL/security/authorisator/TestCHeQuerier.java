/*******************************************************************************
 * Copyright 2017 2011 Universidad Politécnica de Madrid
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

/**
 * @author amedrano
 *
 */
public class TestCHeQuerier extends TestCase {

	public void testSplit(){
		String query = CHeQuerrier.getQuery(CHeQuerrier.getResource("testOrig"), new String[]{});
		//System.out.println(query);
		String [] res = CHeQuerrier.splitPrefixes(query);
		//System.out.println(res[1]);
	}

}

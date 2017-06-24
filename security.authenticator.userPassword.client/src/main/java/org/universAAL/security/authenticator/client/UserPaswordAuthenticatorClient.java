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

package org.universAAL.security.authenticator.client;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.utils.LogUtils;
import org.universAAL.middleware.service.CallStatus;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.service.ServiceResponse;
import org.universAAL.middleware.service.owls.process.ProcessOutput;
import org.universAAL.middleware.xsd.Base64Binary;
import org.universAAL.ontology.cryptographic.Digest;
import org.universAAL.ontology.cryptographic.digest.SecureHashAlgorithm;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.security.AuthenticationService;
import org.universAAL.ontology.security.SecurityOntology;
import org.universAAL.ontology.security.UserPasswordCredentials;

/**
 * This class is a helper for all those components that need to authenticate a
 * user by means of user password authentication.
 *
 * @author amedrano
 *
 */
public class UserPaswordAuthenticatorClient extends DefaultServiceCaller {

	private static final String DIGEST_OUT = SecurityOntology.NAMESPACE + "digestOut";

	private static final String USER_OUT = SecurityOntology.NAMESPACE + "userOut";

	/**
	 * Constructor
	 */
	public UserPaswordAuthenticatorClient(ModuleContext mc) {
		super(mc);
	}

	/**
	 * This method will try to authenticate the user. If successful the user
	 * instance will be returned else it will be null.
	 *
	 * @param username
	 *            the username to authenticate
	 * @param password
	 *            the password to use for the authentication.
	 * @return the {@link User} instance if successful authentication, null
	 *         otherwise.
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public User authenticate(String username, String password) {
		try {
			UserPasswordCredentials cred = new UserPasswordCredentials();
			cred.setUsername(username);

			Set digests = getAllDigestMethods(cred);
			if (digests == null || digests.size() == 0) {
				return null;
			}
			cred.setpassword(new Base64Binary(password.getBytes("UTF-8")));

			Set authUsers = new HashSet();
			for (Iterator i = digests.iterator(); i.hasNext();) {
				Digest d = (Digest) i.next();
				Set users = authenticateUserGivenDigest(cred, d);
				if (users != null || users.size() == 0) {
					HashSet intersection = new HashSet(users);
					intersection.retainAll(authUsers);
					if (intersection.size() > 0) {
						LogUtils.logWarn(owner, getClass(), "authenticate",
								"There are users that have been correctly authenticated through diferent authentication providers!");
					}
					authUsers.addAll(users);
				}
			}

			if (authUsers.size() == 0) {
				return null;
			} else if (authUsers.size() == 1) {
				return (User) authUsers.iterator().next();
			} else {
				String cau = "";
				for (Iterator i = authUsers.iterator(); i.hasNext();) {
					User u = (User) i.next();
					cau.concat("\n\t" + u.getURI());
				}
				LogUtils.logError(owner, getClass(), "authenticate",
						"There is more than one user who can be authenticated with the provided credentials, these are their URIs:");
				return null;
			}

		} catch (UnsupportedEncodingException e) {
			LogUtils.logError(owner, getClass(), "authenticate",
					new String[] {
							"My eyes have yet to see this ... your system is NOT COMPATIBLE with UTF-8??? WTF-8!!" },
					e);
			return null;
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private Set getAllDigestMethods(UserPasswordCredentials cred) {
		ServiceRequest sr1 = new ServiceRequest(new AuthenticationService(), null);
		sr1.addRequiredOutput(DIGEST_OUT, new String[] { AuthenticationService.PROP_GIVEN_CREDENTIALS,
				UserPasswordCredentials.PROP_PASSWORD_DIGEST });
		sr1.addValueFilter(
				new String[] { AuthenticationService.PROP_GIVEN_CREDENTIALS, UserPasswordCredentials.PROP_USERNAME },
				cred.getUsername());
		// TODO ensure the call is not serialized local or remotely
		// sr1.setOriginScope(sr1.ONLY_LOCAL_SCOPE);
		ServiceResponse so = call(sr1);
		if (!so.getCallStatus().equals(CallStatus.succeeded))
			return null;
		// Digest digest = (Digest) so.getOutput(DIGEST_OUT, true).get(0);
		List<ProcessOutput> out = so.getOutputs();
		if (out == null) {
			return null;
		}
		Set allDigests = new HashSet();
		for (Iterator i = out.iterator(); i.hasNext();) {
			ProcessOutput po = (ProcessOutput) i.next();
			allDigests.add(po.getParameterValue());
		}
		return allDigests;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private Set authenticateUserGivenDigest(UserPasswordCredentials origCred, Digest digest) {
		UserPasswordCredentials cred = (UserPasswordCredentials) origCred.deepCopy();
		cred.setDigestAlgorithm(digest);
		try {
			MessageDigest dig = getMD(digest);
			Base64Binary pwd = new Base64Binary(dig.digest(cred.getPassword().getVal()));
			cred.setDigestAlgorithm(digest);
			cred.setpassword(pwd);
		} catch (NoSuchAlgorithmException e) {
			LogUtils.logWarn(owner, getClass(), "authenticate",
					new String[] { "unable to encrupt Password in " + digest }, e);
			return null;
		}

		ServiceRequest sr2 = new ServiceRequest(new AuthenticationService(), null);
		sr2.addRequiredOutput(USER_OUT, new String[] { AuthenticationService.PROP_AUTHENTICATED_USER });
		sr2.addValueFilter(new String[] { AuthenticationService.PROP_GIVEN_CREDENTIALS }, cred);
		ServiceResponse so = call(sr2);
		List<ProcessOutput> outs = so.getOutputs();
		Set users = new HashSet();
		for (Iterator i = outs.iterator(); i.hasNext();) {
			ProcessOutput po = (ProcessOutput) i.next();
			users.add(po.getParameterValue());
		}
		return users;
	}

	private MessageDigest getMD(Digest digestAlgorithm) throws NoSuchAlgorithmException {
		// TODO call encryption service for a fully dynamic way to do this
		if (digestAlgorithm == org.universAAL.ontology.cryptographic.digest.MessageDigest.IND_MD2) {
			return MessageDigest.getInstance("MD2");
		}
		if (digestAlgorithm == org.universAAL.ontology.cryptographic.digest.MessageDigest.IND_MD5) {
			return MessageDigest.getInstance("MD5");
		}
		if (digestAlgorithm == SecureHashAlgorithm.IND_SHA) {
			return MessageDigest.getInstance("SHA");
		}
		if (digestAlgorithm == SecureHashAlgorithm.IND_SHA256) {
			return MessageDigest.getInstance("SHA-256");
		}
		if (digestAlgorithm == SecureHashAlgorithm.IND_SHA384) {
			return MessageDigest.getInstance("SHA-384");
		}
		if (digestAlgorithm == SecureHashAlgorithm.IND_SHA512) {
			return MessageDigest.getInstance("SHA-512");
		}
		throw new NoSuchAlgorithmException();
	}
}

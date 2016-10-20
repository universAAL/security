package org.universAAL.security.authorisator;

import org.universAAL.itests.IntegrationTest;
import org.universAAL.middleware.container.ModuleContext;
import org.universAAL.middleware.container.osgi.uAALBundleContainer;
import org.universAAL.middleware.owl.TypeURI;
import org.universAAL.middleware.service.DefaultServiceCaller;
import org.universAAL.middleware.service.ServiceRequest;
import org.universAAL.middleware.xsd.Base64Binary;
import org.universAAL.ontology.cryptographic.digest.MessageDigest;
import org.universAAL.ontology.profile.AssistedPerson;
import org.universAAL.ontology.profile.User;
import org.universAAL.ontology.profile.UserProfile;
import org.universAAL.ontology.profile.service.ProfilingService;
import org.universAAL.ontology.security.AccessRight;
import org.universAAL.ontology.security.AccessType;
import org.universAAL.ontology.security.DelegationForm;
import org.universAAL.ontology.security.Role;
import org.universAAL.ontology.security.SecuritySubprofile;
import org.universAAL.ontology.security.UserPasswordCredentials;
import org.universAAL.security.authorisator.utils.ProfilingServerHelper;

/**
 * Here developer's of this artifact should code their integration tests.
 * 
 * @author rotgier
 * 
 */
public class ArtifactIT extends IntegrationTest {

    private static final String NAMESPACE = "http://ontology.universAAL.org/AuthorisatorTest.owl#";
    private static final String ARG_OUT = NAMESPACE+"argout";

    
    
    
    /**
	 * 
	 */
	public ArtifactIT() {
		super();
		setIgnoreLastBudnle(true);
	}

	public void testComposite() {
	logAllBundles();
	try {
	    Thread.sleep(5000L);
	} catch (InterruptedException e) {
	    e.printStackTrace();
	}
    }

    public void testRoles() {
    	ModuleContext mc = uAALBundleContainer.THE_CONTAINER
    			.registerModule(new Object[] { bundleContext });
    	
    	ProfilingServerHelper psh = new ProfilingServerHelper(mc);
    	
    	User u1 = new AssistedPerson(NAMESPACE+"user1");
    	UserPasswordCredentials upc = new UserPasswordCredentials();
    	upc.setpassword(new Base64Binary(new byte[]{}));
    	upc.setUsername("user1");
    	upc.setDigestAlgorithm(MessageDigest.IND_MD5);
    	psh.addUser(u1, upc);
    	
    	SecuritySubprofile sspu1  = psh.getSecuritySubprofileForUser(u1);
    	
    	DefaultServiceCaller caller = new DefaultServiceCaller(mc);
    	
    	Role newRole = new Role();
    	AccessRight ar = new AccessRight();
    	ar.addAccessType(AccessType.add);
    	ar.addAccessType(AccessType.change);
    	ar.addAccessType(AccessType.remove);
    	ar.addAccessType(AccessType.read);
    	ar.setAccessTo(new TypeURI(DelegationForm.MY_URI, false));
    	newRole.addAccessRight(ar);
    	newRole.setResourceLabel("Manager of All Delegation Forms");
    	
    	ServiceRequest sreq = new ServiceRequest(new ProfilingService(),u1);
    	sreq.addValueFilter(new String[] {ProfilingService.PROP_CONTROLS,User.PROP_HAS_PROFILE,UserProfile.PROP_HAS_SUB_PROFILE}, sspu1);
    	sreq.addAddEffect(new String[] {ProfilingService.PROP_CONTROLS,User.PROP_HAS_PROFILE,UserProfile.PROP_HAS_SUB_PROFILE,SecuritySubprofile.PROP_ROLES}, newRole);
    	
	
    }



}

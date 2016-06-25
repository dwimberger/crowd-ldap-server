package net.wimpi.crowd.ldap;

import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.service.client.CrowdClient;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.authn.AbstractAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.MessageFormat;import java.util.ResourceBundle;

/**
 * Implements {@class AbstractAuthenticator} to authenticate against using
 * a CrowdClient.
 *
 * @author Dieter Wimberger (dieter at wimpi dot net)
 */
public class CrowdAuthenticator extends AbstractAuthenticator {

  private static final Logger log = LoggerFactory.getLogger(CrowdAuthenticator.class);
  private static final ResourceBundle c_ResourceBundle =
      ResourceBundle.getBundle("net.wimpi.crowd.ldap.strings");

  private CrowdClient m_CrowdClient;
  private DirectoryService service;

  public CrowdAuthenticator(CrowdClient client, DirectoryService service) {
    super(AuthenticationLevel.SIMPLE);
    m_CrowdClient = client;
    this.service = service;
  }//constructor

  public LdapPrincipal authenticate(BindOperationContext ctx) throws Exception {
    String user = ctx.getDn().getRdn(0).getNormValue();
    String pass = new String(ctx.getCredentials(),"utf-8");

    try {
      User u = m_CrowdClient.authenticateUser(user, pass);
      if(u == null) {
        log.debug(c_ResourceBundle.getString("crowdauthenticator.authentication.failed") + "()::Authentication failed");
        throw new javax.naming.AuthenticationException("Invalid credentials for user: " + user);
      } else {
        log.debug(MessageFormat.format(c_ResourceBundle.getString("crowdauthenticator.user"), u.toString()));
        return new LdapPrincipal(this.service.getSchemaManager(), ctx.getDn(), AuthenticationLevel.SIMPLE);
      }
    } catch (Exception ex) {
      log.debug(c_ResourceBundle.getString("crowdauthenticator.authentication.failed") + "()::Authentication failed: " + ex );
      throw new javax.naming.NamingException("Unable to perform authentication: " + ex);
    }
  }//authenticate

}//class CrowdAuthenticator

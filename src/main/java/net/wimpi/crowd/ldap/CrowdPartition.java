package net.wimpi.crowd.ldap;

import com.atlassian.crowd.embedded.api.SearchRestriction;
import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.search.query.entity.restriction.MatchMode;
import com.atlassian.crowd.search.query.entity.restriction.NullRestrictionImpl;
import com.atlassian.crowd.search.query.entity.restriction.TermRestriction;
import com.atlassian.crowd.search.query.entity.restriction.constants.GroupTermKeys;
import com.atlassian.crowd.search.query.entity.restriction.constants.UserTermKeys;
import com.atlassian.crowd.service.client.CrowdClient;
import net.wimpi.crowd.ldap.util.LRUCacheMap;
import org.apache.directory.server.core.entry.ClonedServerEntry;
import org.apache.directory.server.core.filtering.BaseEntryFilteringCursor;
import org.apache.directory.server.core.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.interceptor.context.*;
import org.apache.directory.server.core.partition.Partition;
import org.apache.directory.shared.ldap.constants.SchemaConstants;
import org.apache.directory.shared.ldap.cursor.EmptyCursor;
import org.apache.directory.shared.ldap.cursor.ListCursor;
import org.apache.directory.shared.ldap.cursor.SingletonCursor;
import org.apache.directory.shared.ldap.entry.DefaultServerEntry;
import org.apache.directory.shared.ldap.entry.ServerEntry;
import org.apache.directory.shared.ldap.name.DN;
import org.apache.directory.shared.ldap.name.RDN;
import org.apache.directory.shared.ldap.schema.SchemaManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.OperationNotSupportedException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A partition that bridges to the CrowdClient/Crowd REST interface.
 *
 * Currently this implementation is read only.
 *
 * @author Dieter Wimberger
 */
public class CrowdPartition implements Partition {

  private static final Logger log = LoggerFactory.getLogger(CrowdPartition.class);

  private String m_ID;
  private AtomicBoolean m_Initialized;
  private LRUCacheMap<String, ServerEntry> m_EntryCache;

  private SchemaManager m_SchemaManager;
  private String m_Suffix = CROWD_DN;

  private ServerEntry m_CrowdEntry;
  private ServerEntry m_CrowdGroupsEntry;
  private ServerEntry m_CrowdUsersEntry;

  private CrowdClient m_CrowdClient;

  private List<ServerEntry> m_CrowdOneLevelList;
  private Pattern m_UIDFilter = Pattern.compile("\\(0.9.2342.19200300.100.1.1=([^\\)]*)\\)");
  //AD memberOf Emulation
  private boolean m_emulateADmemberOf = false;
  private boolean m_includeNested = false;

  public CrowdPartition(CrowdClient client) {
    m_CrowdClient = client;
    m_EntryCache = new LRUCacheMap<String, ServerEntry>(300);
    m_Initialized = new AtomicBoolean(false);
  }//constructor

  public CrowdPartition(CrowdClient client, boolean emulateADMemberOf, boolean includeNested) {
    m_CrowdClient = client;
    m_EntryCache = new LRUCacheMap<String, ServerEntry>(300);
    m_Initialized = new AtomicBoolean(false);
    m_emulateADmemberOf = emulateADMemberOf;
    m_includeNested = includeNested;
  }//constructor

  public void initialize() throws Exception {
    if (!m_Initialized.getAndSet(true)) {
      log.debug("==> CrowdPartition::init");

      String infoMsg = String.format("Initializing %s with m_Suffix %s", this
          .getClass().getSimpleName(), m_Suffix);
      log.info(infoMsg);

      // Create LDAP DN
      DN crowdDN = new DN(m_Suffix);
      crowdDN.normalize(
          m_SchemaManager.getRegistries().getAttributeTypeRegistry()
              .getNormalizerMapping()
      );
      RDN rdn = crowdDN.getRdn();

      // Create crowd entry
      /*
       dn: dc=example,dc=com
       objectclass: top
       objectclass: domain
       dc: crowd
       description: Crowd Domain
      */

      ServerEntry dcEntry = new DefaultServerEntry(
          m_SchemaManager,
          crowdDN
      );
      dcEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, SchemaConstants.DOMAIN_OC);
      dcEntry.put(SchemaConstants.DC_AT, rdn.getUpValue().toString());
      dcEntry.put("description", "Crowd Domain");
      m_CrowdEntry = dcEntry;

      // Create group entry
      /*
      dn: ou=groups, dc=crowd
      objectClass: top
      objectClass: organizationalUnit
      ou: groups
      */
      DN groupDn = new DN(CROWD_GROUPS_DN);
      ServerEntry groupEntry = new DefaultServerEntry(
          m_SchemaManager,
          groupDn
      );
      groupEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATIONAL_UNIT_OC);
      groupEntry.put(SchemaConstants.OU_AT, "groups");
      groupEntry.put("description", "Crowd Groups");
      m_CrowdGroupsEntry = groupEntry;

      // Create users entry
      /*
      dn: ou=users, dc=crowd
      objectClass: top
      objectClass: organizationalUnit
      ou: users
      */
      DN usersDn = new DN(CROWD_USERS_DN);
      ServerEntry usersEntry = new DefaultServerEntry(
          m_SchemaManager,
          usersDn
      );
      usersEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATIONAL_UNIT_OC);
      usersEntry.put(SchemaConstants.OU_AT, "users");
      usersEntry.put("description", "Crowd Users");
      m_CrowdUsersEntry = usersEntry;

      //Prepare list
      m_CrowdOneLevelList = new ArrayList<ServerEntry>();
      m_CrowdOneLevelList.add(m_CrowdGroupsEntry);
      m_CrowdOneLevelList.add(m_CrowdUsersEntry);
      m_CrowdOneLevelList = Collections.unmodifiableList(m_CrowdOneLevelList);

      //Add to cache
      m_EntryCache.put(crowdDN.getName(), m_CrowdEntry);
      m_EntryCache.put(groupDn.getName(), groupEntry);
      m_EntryCache.put(usersDn.getName(), usersEntry);
    }
    log.debug("<== CrowdPartition::init");
  }//initialize

  public boolean isInitialized() {
    return m_Initialized.get();
  }//isInitialized

  public void destroy() throws Exception {
    log.info("destroying partition");
    m_CrowdClient.shutdown();
  }//destroy

  public DN getSuffixDn() {
    return m_CrowdEntry.getDn();
  }//getSuffixDn

  public String getSuffix() {
    return m_Suffix;
  }//getSuffix

  /**
   * @throws IllegalArgumentException if m_Suffix does not start with dc=
   */
  public void setSuffix(String suffix) {
    if (!suffix.startsWith("dc=")) {
      throw new IllegalArgumentException("m_Suffix has to start with dc");
    }
    m_Suffix = suffix;
  }//setSuffix

  public SchemaManager getSchemaManager() {
    return m_SchemaManager;
  }//getSchemaManager

  public void setSchemaManager(SchemaManager schemaManager) {
    m_SchemaManager = schemaManager;
  }//setSchemaManager

  public String getId() {
    return m_ID;
  }//getId

  public void setId(String id) {
    this.m_ID = id;
  }//setId

  public int getCacheSize() {
    return m_EntryCache.getCeiling();
  }//getCacheSize

  public void setCacheSize(int cacheSize) {
    m_EntryCache.setCeiling(cacheSize);
  }//setCacheSize


  private boolean isCrowd(DN dn) {
    return m_CrowdEntry.getDn().equals(dn);
  }//isCrowd

  private boolean isCrowdGroups(DN dn) {
    return m_CrowdGroupsEntry.getDn().getName().equals(dn.getName());
  }//isCrowdGroups

  private boolean isCrowdUsers(DN dn) {
    return m_CrowdUsersEntry.getDn().getName().equals(dn.getName());
  }//isCrowdUsers


  public boolean hasEntry(EntryOperationContext ctx) throws UserNotFoundException, InvalidAuthenticationException, ApplicationPermissionException, OperationFailedException {
    DN dn = ctx.getDn();
    /*
    if (log.isDebugEnabled()) {
      log.debug("hasEntry(dn=" + ctx.getDn() + ")");
      //log.debug("" + m_CrowdEntry.getDn());
      //log.debug("" + m_CrowdGroupsEntry.getDn() + ((m_CrowdGroupsEntry.equals(ctx.getName()))?" EQUAL":" NOT EQUAL"));
      //log.debug("" + m_CrowdUsersEntry.getDn());

      for (int i = 0; i < dn.size(); i++) {
        log.debug("DN.get(" + i + ")" + dn.get(i));
        log.debug("DN.getSuffix(" + i + ")" + dn.getSuffix(i));
        log.debug("DN.getPrefix(" + i + ")" + dn.getPrefix(i));
        log.debug("DN.getRdn(" + i + ")" + dn.getRdn(i));
      }
    }
    */
    if (m_EntryCache.containsKey(ctx.getDn())) {
      return true;
    } else {
      int dnSize = dn.size();

      if (dnSize == 1) {
        if (isCrowd(dn)) {
          m_EntryCache.put(dn.getName(), m_CrowdEntry);
          return true;
        } else {
          return false;
        }
      } else if (dnSize == 2) {
        if (isCrowdGroups(dn)) {
          m_EntryCache.put(dn.getName(), m_CrowdGroupsEntry);
          return true;
        } else if (isCrowdUsers(dn)) {
          m_EntryCache.put(dn.getName(), m_CrowdUsersEntry);
          return true;
        } else {
          return false;
        }
      } else if (dnSize == 3) {
        DN prefix = dn.getPrefix(2);
        try {
          prefix.normalize(m_SchemaManager.getNormalizerMapping());
        } catch (Exception ex) {
          log.error("hasEntry()", ex);
        }
        log.debug("Prefix=" + prefix);
        if (isCrowdUsers(prefix)) {
          RDN rdn = dn.getRdn(2);
          String user = rdn.getNormValue();
          log.debug("user=" + user);
          ServerEntry userEntry = createUserEntry(dn);
          return (userEntry != null);
        } else if(isCrowdGroups(prefix)) {
          RDN rdn = dn.getRdn(2);
          String group = rdn.getNormValue();
          log.debug("group=" + group);
          ServerEntry groupEntry = createGroupEntry(dn);
          return (groupEntry != null);        
        } else {
          log.debug("Prefix is neither users nor groups");
          log.debug("Crowd Users = " + m_CrowdUsersEntry.getDn());
          log.debug("Crowd Groups = " + m_CrowdGroupsEntry.getDn().toString());
          return false;
        }
      }

    }
    return false;
  }//hasEntry

  public ServerEntry createUserEntry(DN dn) {
    ServerEntry userEntry = m_EntryCache.get(dn.getName());
    if (userEntry == null) {
      try {
        //1. Obtain from Crowd
        RDN rdn = dn.getRdn(2);
        String user = rdn.getNormValue();

        User u = m_CrowdClient.getUser(user);
        if (u == null) {
          return null;
        }
        
        //2. Create entry
        userEntry = new DefaultServerEntry(
            m_SchemaManager,
            dn
        );
        userEntry.put(SchemaConstants.OBJECT_CLASS, SchemaConstants.INET_ORG_PERSON_OC);
        userEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATIONAL_PERSON_OC, SchemaConstants.PERSON_OC, SchemaConstants.INET_ORG_PERSON_OC);
        userEntry.put(SchemaConstants.CN_AT, u.getDisplayName());
        userEntry.put(SchemaConstants.UID_AT,user);
        userEntry.put("mail", u.getEmailAddress());
        userEntry.put("givenname", u.getFirstName());
        userEntry.put(SchemaConstants.SN_AT, u.getLastName());
        userEntry.put(SchemaConstants.OU_AT, "users");

		//Note: Emulate AD memberof attribute 
        if(m_emulateADmemberOf) {
	        //groups
    	    List<String> groups = m_CrowdClient.getNamesOfGroupsForUser(user, 0, Integer.MAX_VALUE); 
        	for (String g : groups) {
          		DN mdn = new DN(String.format("cn=%s,%s", g, CROWD_GROUPS_DN));
          		userEntry.add("memberof", mdn.getName());
        	}
        	if(m_includeNested) {
        		//groups
    	    	groups = m_CrowdClient.getNamesOfGroupsForNestedUser(user, 0, Integer.MAX_VALUE); 
        		for (String g : groups) {
          			DN mdn = new DN(String.format("cn=%s,%s", g, CROWD_GROUPS_DN));
          			userEntry.add("memberof", mdn.getName());
        		}
        	}
        }    
            

        log.debug(userEntry.toString());

        m_EntryCache.put(dn.getName(), userEntry);
      } catch (Exception ex) {
        log.debug("createUserEntry()", ex);
      }
    }
    return userEntry;
  }//createUserEntry

  public ServerEntry createGroupEntry(DN dn) {
    ServerEntry groupEntry = m_EntryCache.get(dn.getName());
    if (groupEntry == null) {
      try {
        //1. Obtain from crowd
        RDN rdn = dn.getRdn(2);
        String group = rdn.getNormValue();

        Group g = m_CrowdClient.getGroup(group);
        List<String> users = m_CrowdClient.getNamesOfUsersOfGroup(group, 0, Integer.MAX_VALUE);

        groupEntry = new DefaultServerEntry(
            m_SchemaManager,
            dn
        );
        groupEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.GROUP_OF_NAMES_OC);
        groupEntry.put(SchemaConstants.CN_AT, g.getName());
        groupEntry.put("description", g.getDescription());

        for (String u : users) {
          DN mdn = new DN(String.format("dn=%s,%s", u, CROWD_USERS_DN));
          groupEntry.add(SchemaConstants.MEMBER_AT, mdn.getName());
        }
        m_EntryCache.put(dn.getName(), groupEntry);
      } catch (Exception ex) {
        log.debug("createGroupEntry()", ex);
      }
    }
    return groupEntry;
  }//createUserEntry


  public ClonedServerEntry lookup(LookupOperationContext ctx) {
    DN dn = ctx.getDn();
    /*
        if (log.isDebugEnabled()) {
          log.debug("lookup(dn=" + ctx.getDn() + ")");

          for (int i = 0; i < dn.size(); i++) {
            log.debug("DN.get(" + i + ")" + dn.get(i));
            log.debug("DN.getSuffix(" + i + ")" + dn.getSuffix(i));
            log.debug("DN.getPrefix(" + i + ")" + dn.getPrefix(i));
            log.debug("DN.getRdn(" + i + ")" + dn.getRdn(i));
          }
        }
    */
    ServerEntry se = m_EntryCache.get(ctx.getDn().getName());
    if (se == null) {
      //todo
      log.debug("lookup()::No cached entry found for " + dn.getName());
      return null;
    } else {
      log.debug("lookup()::Cached entry found for " + dn.getName());
      return new ClonedServerEntry(se);
    }
  }//lookup

  private BaseEntryFilteringCursor findObject(SearchingOperationContext ctx) {
    DN dn = ctx.getDn();
    String dnName = dn.getName();
    ServerEntry se = ctx.getEntry();

    log.debug("findObject()::dn=" + dnName + "::entry=" + se.toString());

    //1. Try cache
    se = m_EntryCache.get(dn.getName());
    if (se != null) {
      return new BaseEntryFilteringCursor(
          new SingletonCursor<ServerEntry>(se), ctx);
    }
    // return an empty result
    return new BaseEntryFilteringCursor(new EmptyCursor<ServerEntry>(), ctx);
  }//findObject

  private BaseEntryFilteringCursor findOneLevel(SearchOperationContext ctx) {
    DN dn = ctx.getDn();
    ServerEntry se = ctx.getEntry();

    if(se == null) {
        String name = dn.getRdn(0).getNormValue();
        log.debug("Name=" + name);
        if("crowd".equals(name)) {
          return new BaseEntryFilteringCursor(new EmptyCursor<ServerEntry>(), ctx);
        }
    }
    log.debug("findOneLevel()::dn=" + dn.getName() + "::entry=" + se.toString() + "::filter=" + ctx.getFilter().toString());

    //1. Organizational Units
    if (dn.getName().equals(m_CrowdEntry.getDn().getName())) {
      return new BaseEntryFilteringCursor(
          new ListCursor<ServerEntry>(m_CrowdOneLevelList),
          ctx
      );
    }
    //2. Groups
    if (dn.getName().equals(m_CrowdGroupsEntry.getDn().getName())) {
      //Retrieve Filter
      if (ctx.getFilter().toString().contains("(2.5.4.0=*)")) {

        List<ServerEntry> l = new ArrayList<ServerEntry>();
        try {
          TermRestriction<String> groupName = new TermRestriction<String>(GroupTermKeys.NAME, MatchMode.CONTAINS, "");
          List<String> list = m_CrowdClient.searchGroupNames(groupName, 0, Integer.MAX_VALUE);
          for (String gn : list) {
            DN gdn = new DN(String.format("dn=%s,%s", gn, CROWD_GROUPS_DN));
            l.add(createGroupEntry(gdn));
          }
        } catch (Exception ex) {
          log.error("findOneLevel()", ex);
        }
        return new BaseEntryFilteringCursor(
            new ListCursor<ServerEntry>(l),
            ctx
        );
      }
    }

    //3. Users
    if (dn.getName().equals(m_CrowdUsersEntry.getDn().getName())) {
      //Retrieve Filter
      String filter = ctx.getFilter().toString();
      if (filter.contains("(2.5.4.0=*)") ||  filter.contains("(2.5.4.0=referral)")) {


        Matcher m = m_UIDFilter.matcher(filter);
        String uid = "";
        if (m.find()) {
          uid=m.group(1);
        }

        List<ServerEntry> l = new ArrayList<ServerEntry>();
        try {
          SearchRestriction userName = null;
          if ("*".equals(uid)) {
              // Contains * term restriction does not return any users, so use null one
              userName = NullRestrictionImpl.INSTANCE;
              
          } else {
              userName = new TermRestriction<String>(UserTermKeys.USERNAME, MatchMode.CONTAINS, uid);
          }
          List<String> list = m_CrowdClient.searchUserNames(userName, 0, Integer.MAX_VALUE);
          for (String gn : list) {
            DN udn = new DN(String.format("dn=%s,%s", gn, CROWD_USERS_DN));
            l.add(createUserEntry(udn));
          }
        } catch (Exception ex) {
          log.error("findOneLevel()", ex);
        }
        return new BaseEntryFilteringCursor(
            new ListCursor<ServerEntry>(l),
            ctx
        );
      }
    }

    // return an empty result
    return new BaseEntryFilteringCursor(new EmptyCursor<ServerEntry>(), ctx);
  }//findOneLevel

  private BaseEntryFilteringCursor findSubTree(SearchOperationContext ctx) {
    DN dn = ctx.getDn();

    log.debug("findSubTree()::dn=" + dn.getName());
    //Will only search at one level
    return findOneLevel(ctx);
  }//findSubTree

  public EntryFilteringCursor search(SearchOperationContext ctx)
      throws Exception {

    /*
        -base: the node itself
        -one: one level under the node
        -sub: all node under the node
    */

    if (log.isDebugEnabled()) {
      log.debug("search((dn=" + ctx.getDn() + ", filter="
          + ctx.getFilter() + ", scope=" + ctx.getScope() + ")");
    }

    switch (ctx.getScope()) {
      case OBJECT:
        return findObject(ctx);
      case ONELEVEL:
        return findOneLevel(ctx);
      case SUBTREE:
        return findSubTree(ctx);
      default:
        // return an empty result
        return new BaseEntryFilteringCursor(new EmptyCursor<ServerEntry>(), ctx);
    }
  }//search

  public EntryFilteringCursor list(ListOperationContext opContext) {
    log.debug("list()::opContext=" + opContext.toString());
    return null;
  }//list

  public ClonedServerEntry lookup(Long id) {
    log.debug("lookup::id=" + id.toString());
    return null;
  }//lookup


  public void bind(BindOperationContext opContext) throws Exception {
    log.debug("bind()::opContext=" + opContext.toString());

  }//bind

  public void unbind(UnbindOperationContext opContext) throws Exception {
    log.debug("unbind()::opContext=" + opContext.toString());
  }//unbind


  // The following methods are not supported by this partition, because it is
  // readonly.

  public void add(AddOperationContext opContext)
      throws OperationNotSupportedException {
    throw new OperationNotSupportedException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }

  public void delete(DeleteOperationContext opContext)
      throws OperationNotSupportedException {
    throw new OperationNotSupportedException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }

  public void modify(ModifyOperationContext ctx)
      throws OperationNotSupportedException {
    throw new OperationNotSupportedException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }

  public void move(MoveOperationContext opContext)
      throws OperationNotSupportedException {
    throw new OperationNotSupportedException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }

  public void rename(RenameOperationContext opContext)
      throws OperationNotSupportedException {
    throw new OperationNotSupportedException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }//rename

  public void moveAndRename(MoveAndRenameOperationContext opContext)
      throws OperationNotSupportedException {
    throw new OperationNotSupportedException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }//moveAndRename

  public void sync() {
  }//snyc

  private static final String CROWD_DN = "dc=crowd";
  private static final String CROWD_GROUPS_DN = "ou=groups,dc=crowd";
  private static final String CROWD_USERS_DN = "ou=users,dc=crowd";

  /**
   * Error message, if someone tries to modify the partition
   */
  private static final String MODIFICATION_NOT_ALLOWED_MSG = "This simple partition does not allow modification.";

}//class CrowdPartition
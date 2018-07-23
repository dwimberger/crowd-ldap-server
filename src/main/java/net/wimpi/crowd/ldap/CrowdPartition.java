package net.wimpi.crowd.ldap;

import com.atlassian.crowd.embedded.api.SearchRestriction;
import com.atlassian.crowd.embedded.api.UserWithAttributes;
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
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.EmptyCursor;
import org.apache.directory.api.ldap.model.cursor.ListCursor;
import org.apache.directory.api.ldap.model.cursor.SingletonCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.entry.ClonedServerEntry;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.context.*;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.partition.Subordinates;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.directory.server.core.api.filtering.*;

import javax.naming.OperationNotSupportedException;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.Math.abs;

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
  private LRUCacheMap<String, Entry> m_EntryCache;

  private SchemaManager m_SchemaManager;
  private String m_Suffix = CROWD_DN;

  private Entry m_CrowdEntry;
  private Entry m_CrowdGroupsEntry;
  private Entry m_CrowdUsersEntry;

  private CrowdClient m_CrowdClient;

  private String m_gid_cn;
  private String m_gid_ou;
  private String m_gid_dc;
  private Integer m_gid;

  private List<Entry> m_CrowdOneLevelList;
  private Pattern m_UIDFilter = Pattern.compile("\\(0.9.2342.19200300.100.1.1=([^\\)]*)\\)");
  private Pattern uidFilter = Pattern.compile("\\(uid=([^\\)]*)\\)");
  private Pattern gidFilter = Pattern.compile("\\(gidNumber=([^\\)]*)\\)");
  //AD memberOf Emulation
  private boolean m_emulateADmemberOf = false;
  private boolean m_includeNested = false;

  public CrowdPartition(CrowdClient client) {
    m_CrowdClient = client;
    m_EntryCache = new LRUCacheMap<String, Entry>(300);
    m_Initialized = new AtomicBoolean(false);
  }//constructor

  public CrowdPartition(CrowdClient client, boolean emulateADMemberOf, boolean includeNested,String mgidcn,String mgiddc, String mgidou,Integer mgid) {
    m_CrowdClient = client;
    m_EntryCache = new LRUCacheMap<String, Entry>(300);
    m_Initialized = new AtomicBoolean(false);
    m_emulateADmemberOf = emulateADMemberOf;
    m_includeNested = includeNested;
    m_gid_cn = mgidcn;
    m_gid_dc = mgiddc;
    m_gid_ou = mgidou;
    m_gid = mgid;
  }//constructor

  public void initialize() {
    if (!m_Initialized.getAndSet(true)) {
      log.debug("==> CrowdPartition::init");

      String infoMsg = String.format("Initializing %s with m_Suffix %s", this
          .getClass().getSimpleName(), m_Suffix);
      log.info(infoMsg);

      // Create LDAP Dn
      Dn crowdDn = null;
      try {
        crowdDn = new Dn(this.m_SchemaManager, m_Suffix);
      } catch (LdapInvalidDnException e) {
        e.printStackTrace();
      }

      Rdn rdn = crowdDn.getRdn();

      // Create crowd entry
      /*
       dn: dc=example,dc=com
       objectclass: top
       objectclass: domain
       dc: crowd
       description: Crowd Domain
      */

      Entry dcEntry = new DefaultEntry(
          m_SchemaManager,
          crowdDn
      );

      dcEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, SchemaConstants.DOMAIN_OC);
      dcEntry.put(SchemaConstants.DC_AT, rdn.getAva().getValue().toString());
      dcEntry.put("description", "Crowd Domain");
      m_CrowdEntry = dcEntry;

      // Create group entry
      /*
      dn: ou=groups, dc=crowd
      objectClass: top
      objectClass: organizationalUnit
      ou: groups
      */
      Dn groupDn = null;
      try {
        groupDn = new Dn(this.m_SchemaManager, CROWD_GROUPS_DN);
      } catch (LdapInvalidDnException e) {
        e.printStackTrace();
      }

      Entry groupEntry = new DefaultEntry(
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
      Dn usersDn = null;
      try {
        usersDn = new Dn(this.m_SchemaManager, CROWD_USERS_DN);
      } catch (LdapInvalidDnException e) {
        e.printStackTrace();
      }
      DefaultEntry usersEntry = new DefaultEntry(
            m_SchemaManager,
            usersDn
        );

      usersEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATIONAL_UNIT_OC);
      usersEntry.put(SchemaConstants.OU_AT, "users");
      usersEntry.put("description", "Crowd Users");
      m_CrowdUsersEntry = usersEntry;

      //Prepare list
      m_CrowdOneLevelList = new ArrayList<Entry>();
      m_CrowdOneLevelList.add(m_CrowdGroupsEntry);
      m_CrowdOneLevelList.add(m_CrowdUsersEntry);
      m_CrowdOneLevelList = Collections.unmodifiableList(m_CrowdOneLevelList);

      //Add to cache
      m_EntryCache.put(crowdDn.getName(), m_CrowdEntry);
      m_EntryCache.put(groupDn.getName(), m_CrowdGroupsEntry);
      m_EntryCache.put(usersDn.getName(), m_CrowdUsersEntry);
    }
    log.debug("<== CrowdPartition::init");
  }//initialize

  @Override
  public void repair() throws Exception {

  }

  public boolean isInitialized() {
    return m_Initialized.get();
  }//isInitialized

  public void destroy() throws Exception {
    log.info("destroying partition");
    m_CrowdClient.shutdown();
  }//destroy

  public Dn getSuffixDn() {
    return m_CrowdEntry.getDn();
  }//getSuffixDn

  @Override
  public void setSuffixDn(Dn dn) throws LdapInvalidDnException {
    m_CrowdEntry.setDn(dn);
  }

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

  private boolean isCrowd(Dn dn) {
    return m_CrowdEntry.getDn().equals(dn);
  }//isCrowd

  private boolean isCrowdGroups(Dn dn) {
    return m_CrowdGroupsEntry.getDn().getName().equals(dn.getName());
  }//isCrowdGroups

  private boolean isCrowdUsers(Dn dn) {
    return m_CrowdUsersEntry.getDn().getName().equals(dn.getName());
  }//isCrowdUsers


  // potentialy problematic but we maybe can found some better
  public static int hash(String s) {
    int h = 0;
    for (int i = 0; i < s.length(); i++) {
      h = h + s.charAt(i);
    }
    return abs(h);
  }


  public Entry createUserEntry(Dn dn) {
    Entry userEntry = m_EntryCache.get(dn.getName());
    if (userEntry == null) {
      try {
        //1. Obtain from Crowd
        Rdn rdn = dn.getRdn(0);
        String user = rdn.getNormValue();


        User u = m_CrowdClient.getUser(user);
        UserWithAttributes uu = m_CrowdClient.getUserWithAttributes(user);
        if (u == null || uu == null) {
          return null;
        }
        
        //2. Create entry
        userEntry = new DefaultEntry(
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
        userEntry.put(SchemaConstants.UID_NUMBER_AT, uu.getValue("uidNumber"));
        userEntry.put(SchemaConstants.HOME_DIRECTORY_AT, "/home/" + user + "/");
        userEntry.put(SchemaConstants.LOGIN_SHELL_AT,"/bin/bash");
        userEntry.put(SchemaConstants.GECOS_AT,"crowd user");


		//Note: Emulate AD memberof attribute
        if(m_emulateADmemberOf) {
	        //groups
    	    List<String> groups = m_CrowdClient.getNamesOfGroupsForUser(user, 0, Integer.MAX_VALUE);
        	for (String g : groups) {
              Dn mdn = new Dn(this.m_SchemaManager, String.format("cn=%s,%s", g, CROWD_GROUPS_DN));
          		userEntry.add("memberof", mdn.getName());
        	}
        	if(m_includeNested) {
        		//groups
    	    	groups = m_CrowdClient.getNamesOfGroupsForNestedUser(user, 0, Integer.MAX_VALUE);
        		for (String g : groups) {
                    Dn mdn = new Dn(this.m_SchemaManager, String.format("cn=%s,%s", g, CROWD_GROUPS_DN));
                    if (!userEntry.contains("memberof", mdn.getName())) {
                        userEntry.add("memberof", mdn.getName());
                    }
        		}
            }
        }
        if (uu.getValue("gidNumber") != null) {
          userEntry.put(SchemaConstants.GID_NUMBER_AT, uu.getValue("gidNumber"));
        } else {
          // try to get gidNumber from memberOf attributes
          HashMap<String, String> selectedGroup = new HashMap<String, String>();
          selectedGroup.put("cn",m_gid_cn);
          selectedGroup.put("dc",m_gid_dc);
          selectedGroup.put("ou",m_gid_ou);

          ArrayList<String> member = new ArrayList<String>();
          String parsedRoles = userEntry.get("memberof").toString();

          StringTokenizer tokenizer = new StringTokenizer(parsedRoles, System.getProperty("line.separator"));
          while (tokenizer.hasMoreTokens()) {
            member.add(tokenizer.nextToken());
          }

          for (String memberOf : member) {
            HashMap<String, String> eachLineCheck = new HashMap<String, String>();
            eachLineCheck.put("cn", readValueFromFilter(memberOf, "cn="));
            eachLineCheck.put("dc", readValueFromFilter(memberOf, "dc="));
            eachLineCheck.put("ou", readValueFromFilter(memberOf, "ou="));
            if (eachLineCheck.equals(selectedGroup)) {
              userEntry.put(SchemaConstants.GID_NUMBER_AT, String.valueOf(m_gid));
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

  public Entry createGroupEntry(Dn dn) {
    Entry groupEntry = m_EntryCache.get(dn.getName());
    if (groupEntry == null) {
      try {
        //1. Obtain from crowd
        Rdn rdn = dn.getRdn(0);
        String group = rdn.getNormValue();

        Group g = m_CrowdClient.getGroup(group);
        List<String> users = m_CrowdClient.getNamesOfUsersOfGroup(group, 0, Integer.MAX_VALUE);

        groupEntry = new DefaultEntry(
            m_SchemaManager,
            dn
        );
        groupEntry.put(SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.GROUP_OF_NAMES_OC);
        groupEntry.put(SchemaConstants.CN_AT, g.getName());
        groupEntry.put(SchemaConstants.DESCRIPTION_AT, g.getDescription());
        groupEntry.put(SchemaConstants.GID_NUMBER_AT, ""+hash(g.getName()));


        for (String u : users) {
          Dn mdn = new Dn(this.m_SchemaManager, String.format("uid=%s,%s", u, CROWD_USERS_DN));
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
    Dn dn = ctx.getDn();
    /*
        if (log.isDebugEnabled()) {
          log.debug("lookup(dn=" + ctx.getDn() + ")");

          for (int i = 0; i < dn.size(); i++) {
            log.debug("Dn.get(" + i + ")" + dn.get(i));
            log.debug("Dn.getSuffix(" + i + ")" + dn.getSuffix(i));
            log.debug("Dn.getPrefix(" + i + ")" + dn.getPrefix(i));
            log.debug("Dn.getRdn(" + i + ")" + dn.getRdn(i));
          }
        }
    */
    Entry se = m_EntryCache.get(ctx.getDn().getName());
    if (se == null) {
      //todo
      log.debug("lookup()::No cached entry found for " + dn.getName());
      return null;
    } else {
      log.debug("lookup()::Cached entry found for " + dn.getName());
      return new ClonedServerEntry(se);
    }
  }//lookup

  @Override
  public boolean hasEntry(HasEntryOperationContext ctx) throws LdapException {
    Dn dn = ctx.getDn();
    /*
    if (log.isDebugEnabled()) {
      log.debug("hasEntry(dn=" + ctx.getDn() + ")");
      //log.debug("" + m_CrowdEntry.getDn());
      //log.debug("" + m_CrowdGroupsEntry.getDn() + ((m_CrowdGroupsEntry.equals(ctx.getName()))?" EQUAL":" NOT EQUAL"));
      //log.debug("" + m_CrowdUsersEntry.getDn());

      for (int i = 0; i < dn.size(); i++) {
        log.debug("Dn.get(" + i + ")" + dn.get(i));
        log.debug("Dn.getSuffix(" + i + ")" + dn.getSuffix(i));
        log.debug("Dn.getPrefix(" + i + ")" + dn.getPrefix(i));
        log.debug("Dn.getRdn(" + i + ")" + dn.getRdn(i));
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
        Dn prefix = dn.getParent();
        try {
          prefix.apply(m_SchemaManager);
        } catch (Exception ex) {
          log.error("hasEntry()", ex);
        }
        log.debug("Prefix=" + prefix);
        if (isCrowdUsers(prefix)) {
          Rdn rdn = dn.getRdn(2);
          String user = rdn.getNormValue();
          log.debug("user=" + user);
          Entry userEntry = createUserEntry(dn);
          return (userEntry != null);
        } else if(isCrowdGroups(prefix)) {
          Rdn rdn = dn.getRdn(2);
          String group = rdn.getNormValue();
          log.debug("group=" + group);
          Entry groupEntry = createGroupEntry(dn);
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
  }

  private EntryFilteringCursor findObject(SearchOperationContext ctx, ExprNode filter) {
    Dn dn = ctx.getDn();
    String dnName = dn.getName();
    Entry se = ctx.getEntry();
    //log.debug("findObject()::dn=" + dnName + "::entry=" + se.toString());

    //1. Try cache
    se = m_EntryCache.get(dn.getName());
    if (se == null) {
      return new EntryFilteringCursorImpl(new EmptyCursor<Entry>(), ctx,this.m_SchemaManager);
    }

    String filterPreparation = filter.toString();
    if (filterPreparation.contains("(memberOf=")) { // memberOf filter is always threaded with AND condition
      EntryFilteringCursor cursorHelp = filterMemberOf(ctx, se, filterPreparation);
      if (cursorHelp != null) return cursorHelp;
      return new EntryFilteringCursorImpl(new EmptyCursor<Entry>(), ctx,this.m_SchemaManager); // return an empty result
    }
    return new EntryFilteringCursorImpl(new SingletonCursor<Entry>(se), ctx,this.m_SchemaManager);
  }//findObject

  private EntryFilteringCursor filterMemberOf(SearchOperationContext ctx, Entry se, String filterPreparation) {
    HashMap<String, String> parsedFilter = new HashMap<String, String>() {};
    parsedFilter.put("cn", readValueFromFilter(filterPreparation, "2.5.4.3=")); // cn
    parsedFilter.put("ou", readValueFromFilter(filterPreparation, "2.5.4.11=")); // organizationalUnitName
    parsedFilter.put("dc", readValueFromFilter(filterPreparation, "0.9.2342.19200300.100.1.25=")); // domainComponent

    ArrayList<String> member = new ArrayList<String>();
    String parsedRoles = se.get("memberof").toString();

    StringTokenizer tokenizer = new StringTokenizer(parsedRoles,System.getProperty("line.separator"));
    while(tokenizer.hasMoreTokens()) {
      member.add(tokenizer.nextToken());
    }

    for(String memberOf: member)
    {
      HashMap<String,String> eachLineCheck = new HashMap<String, String>(1);
      eachLineCheck.put("cn",readValueFromFilter(memberOf,"cn="));
      eachLineCheck.put("ou",readValueFromFilter(memberOf,"ou="));
      eachLineCheck.put("dc",readValueFromFilter(memberOf,"dc="));
      if(eachLineCheck.equals(parsedFilter)) {
        SingletonCursor<Entry> singletonCursor = new SingletonCursor<Entry>(se);
        EntryFilteringCursorImpl cursorHelp = new EntryFilteringCursorImpl(singletonCursor, ctx,this.m_SchemaManager);
        return cursorHelp;
      }
    }
    return null;
  }

  private String readValueFromFilter(String string, String identifier) {
    if (string.length() < identifier.length()) return "";
    Integer parseFrom = string.lastIndexOf(identifier) + identifier.length(); // start of parse
    String pomstring = string.substring(parseFrom);
    Integer parseTo = pomstring.indexOf(",");
    if(parseTo == -1)
    {
      parseTo = pomstring.indexOf(")");
    }
    if(parseTo == -1)
    {
      parseTo = pomstring.length();
    }
    if (pomstring.length() > 0 && parseTo >= 0 && parseTo <= string.length()) return pomstring.substring(0, parseTo);
    else return "";
  }

  private EntryFilteringCursor findOneLevel(SearchOperationContext ctx) {
    Dn dn = ctx.getDn();
    Entry se = ctx.getEntry();

    if(se == null) {
        String name = dn.getRdn(0).getNormValue();
        log.debug("Name=" + name);
        if("crowd".equals(name)) {
          return new EntryFilteringCursorImpl(new EmptyCursor<Entry>(), ctx, this.m_SchemaManager);
        }
    }

    //1. Organizational Units
    if (dn.getName().equals(m_CrowdEntry.getDn().getName())) {
      return new EntryFilteringCursorImpl(
          new ListCursor<Entry>(m_CrowdOneLevelList),
          ctx,
          this.m_SchemaManager
      );
    }
    //2. Groups
    if (dn.getName().equals(m_CrowdGroupsEntry.getDn().getName())) {
      //Retrieve Filter
      //if (ctx.getFilter().toString().contains("(2.5.4.0=*)")) {

        List<Entry> l = new ArrayList<Entry>();
        try {
          TermRestriction<String> groupName = new TermRestriction<String>(GroupTermKeys.NAME, MatchMode.CONTAINS, "");
          List<String> list = m_CrowdClient.searchGroupNames(groupName, 0, Integer.MAX_VALUE);
          for (String gn : list) {
            Dn gdn = new Dn(this.m_SchemaManager, String.format("uid=%s,%s", gn, CROWD_GROUPS_DN));
            l.add(createGroupEntry(gdn));
          }
        } catch (Exception ex) {
          log.error("findOneLevel()", ex);
        }
        return new EntryFilteringCursorImpl(
            new ListCursor<Entry>(l),
            ctx,
            this.m_SchemaManager
        );
      //}
    }

    //3. Users
    String pom = dn.getName();
    String pom2 = m_CrowdUsersEntry.getDn().getName();
    if (dn.getName().equals(m_CrowdUsersEntry.getDn().getName())) {
      //Retrieve Filter
      String filter = ctx.getFilter().toString();
      //if (filter.contains("(2.5.4.0=*)") ||  filter.contains("(2.5.4.0=referral)")) {


        Matcher m = m_UIDFilter.matcher(filter);
        String uid = "";
        String gid = "";
        if (m.find()) {
          uid=m.group(1);
        }
        Matcher mm = uidFilter.matcher(filter);
        if(mm.find())
        {
          uid=mm.group(1);
        }
        Matcher mmm = gidFilter.matcher(filter);
        if(mmm.find()) // HACK: this is not implemented yet we need to search by custom attribute from m_crowdclient
        {
          //uid=mmm.group(1);
          return null;
        }

        List<Entry> l = new ArrayList<Entry>();
        try {
          SearchRestriction userName = null;
          if ("*".equals(uid)) {
              // Contains * term restriction does not return any users, so use null one
              userName = NullRestrictionImpl.INSTANCE;
              
          } else {
              userName = new TermRestriction<String>(UserTermKeys.USERNAME, MatchMode.EXACTLY_MATCHES, uid);
          }
          List<String> list = m_CrowdClient.searchUserNames(userName, 0, Integer.MAX_VALUE);
          for (String un : list) {
            Dn udn = new Dn(this.m_SchemaManager, String.format("uid=%s,%s", un, CROWD_USERS_DN));
            l.add(createUserEntry(udn));
          }
        } catch (Exception ex) {
          log.error("findOneLevel()", ex);
        }
        return new EntryFilteringCursorImpl(
            new ListCursor<Entry>(l),
            ctx,
            this.m_SchemaManager
        );
      //}
    }

    // return an empty result
    return new EntryFilteringCursorImpl(new EmptyCursor<Entry>(), ctx, this.m_SchemaManager);
  }//findOneLevel

  private EntryFilteringCursor findSubTree(SearchOperationContext ctx) {
    Dn dn = ctx.getDn();

    log.debug("findSubTree()::dn=" + dn.getName());
    //Will only search at one level
    return findOneLevel(ctx);
  }//findSubTree

  public EntryFilteringCursor search(SearchOperationContext ctx) {

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
        return findObject(ctx,ctx.getFilter());
      case ONELEVEL:
        return findOneLevel(ctx);
      case SUBTREE:
        return findSubTree(ctx);
      default:
        // return an empty result
        return new EntryFilteringCursorImpl(new EmptyCursor<Entry>(), ctx, this.m_SchemaManager);
    }
  }//search


  public void bind(BindOperationContext bindContext)
  {
    log.debug("unbind()::opContext=" + bindContext.toString());
  }

  public void unbind(UnbindOperationContext opContext) {
    log.debug("unbind()::opContext=" + opContext.toString());
  }//unbind

  @Override
  public void dumpIndex(OutputStream outputStream, String s) throws IOException {

  }

  @Override
  public void setCacheService(CacheService cacheService) {

  }

  @Override
  public String getContextCsn() {
    return null;
  }

  @Override
  public void saveContextCsn() throws Exception {

  }

  @Override
  public Subordinates getSubordinates(Entry entry) throws LdapException {
    return null;
  }

  // The following methods are not supported by this partition, because it is
  // readonly.

  public void add(AddOperationContext opContext)
      throws LdapException {
    throw new LdapException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }

  public Entry delete(DeleteOperationContext opContext)
      throws LdapException {
    throw new LdapException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }

  public void modify(ModifyOperationContext ctx)
      throws LdapException {
    throw new LdapException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }

  public void move(MoveOperationContext opContext)
      throws LdapException {
    throw new LdapException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }

  public void rename(RenameOperationContext opContext)
      throws LdapException {
    throw new LdapException(
        MODIFICATION_NOT_ALLOWED_MSG);
  }//rename

  public void moveAndRename(MoveAndRenameOperationContext opContext)
      throws LdapException {
    throw new LdapException(
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

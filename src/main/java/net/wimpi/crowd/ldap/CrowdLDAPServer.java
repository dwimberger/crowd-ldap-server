/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package net.wimpi.crowd.ldap;

import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;
import com.atlassian.crowd.service.client.CrowdClient;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.authn.Authenticator;
import org.apache.directory.server.core.partition.Partition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.core.schema.SchemaPartition;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.directory.server.xdbm.Index;
import org.apache.directory.shared.ldap.entry.ServerEntry;
import org.apache.directory.shared.ldap.schema.SchemaManager;
import org.apache.directory.shared.ldap.schema.ldif.extractor.SchemaLdifExtractor;
import org.apache.directory.shared.ldap.schema.ldif.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.shared.ldap.schema.loader.ldif.LdifSchemaLoader;
import org.apache.directory.shared.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.shared.ldap.schema.registries.SchemaLoader;
import org.apache.log4j.PropertyConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.text.MessageFormat;
import java.util.*;

/**
 * Main application taking care for setup and starting the embedded Apache Directory Server
 * (version 1.5.7).
 * <p/>
 * This code is partially derived from the embedded ApacheDS sample code.
 *
 * @author Dieter Wimberger (dieter at wimpi.net)
 */
public class CrowdLDAPServer {

  private static final Logger log = LoggerFactory.getLogger(CrowdLDAPServer.class);

  private static final ResourceBundle c_ResourceBundle =
      ResourceBundle.getBundle("net.wimpi.crowd.ldap.strings");

  //Directory Service
  private DirectoryService service;
  //LDAP Server
  private LdapServer server;
  //Crowd Configuration
  private Properties m_CrowdConfig;
  private CrowdClient m_CrowdClient;

  /**
   * Creates a new instance of the CrowdLDAPServer.
   * Loads the configuration and prepares the Crowd Client side.
   *
   * @throws Exception if configuration loading or crowd client setup did not work.
   */
  public CrowdLDAPServer(File workDir, File confDir) throws Exception {
    try {
      log.debug(c_ResourceBundle.getString("loading.configuration"));
      m_CrowdConfig = new Properties();
      File f = new File(confDir, "crowd.properties");
      m_CrowdConfig.load(new FileReader(f));
      initCrowdClient();
    } catch (Exception ex) {
      log.error("CrowdLDAPServer(File,File)", ex);
    }

    initDirectoryService(workDir);
  }//CrowdLDAPServer


  /**
   * Initializes the Crowd client side.
   *
   * @throws Exception if initialization fails.
   */
  private void initCrowdClient() throws Exception {
    //Prepare Crowd access
    ClientPropertiesImpl crowdClientProperties = ClientPropertiesImpl.newInstanceFromProperties(m_CrowdConfig);
    // Create Crowd Client
    m_CrowdClient = new RestCrowdClientFactory().newInstance(crowdClientProperties);
    m_CrowdClient.testConnection();
  }//initCrowdClient

  /**
   * Add a new partition to the server.
   *
   * @param partitionId The partition Id
   * @param partitionDn The partition DN
   * @return The newly added partition
   * @throws Exception If the partition can't be added
   */
  private Partition addPartition(String partitionId, String partitionDn) throws Exception {
    // Create a new partition named 'foo'.
    JdbmPartition partition = new JdbmPartition();
    partition.setId(partitionId);
    partition.setPartitionDir(new File(service.getWorkingDirectory(), partitionId));
    partition.setSuffix(partitionDn);
    service.addPartition(partition);
    return partition;
  }//addPartition


  /**
   * Add a new partition to the server.
   *
   * @param partitionId The partition Id
   * @param partitionDn The partition DN
   * @return The newly added partition
   * @throws Exception If the partition can't be added
   */
  private Partition addCrowdPartition(String partitionId, String partitionDn) throws Exception {
    // Create a new partition named 'foo'.
    CrowdPartition partition = new CrowdPartition(m_CrowdClient);
    partition.setId(partitionId);
    partition.setSuffix(partitionDn);
    partition.setSchemaManager(service.getSchemaManager());
    partition.initialize();

    service.addPartition(partition);

    return partition;
  }//addCrowdPartition

  /**
   * Add a new set of index on the given attributes
   *
   * @param partition The partition on which we want to add index
   * @param attrs     The list of attributes to index
   */
  private void addIndex(Partition partition, String... attrs) {
    HashSet<Index<?, ServerEntry, Long>> indexedAttributes = new HashSet<Index<?, ServerEntry, Long>>();

    for (String attribute : attrs) {
      indexedAttributes.add(new JdbmIndex<String, ServerEntry>(attribute));
    }

    ((JdbmPartition) partition).setIndexedAttributes(indexedAttributes);
  }//addIndex


  /**
   * initialize the schema manager and add the schema partition to diectory service
   *
   * @throws Exception if the schema LDIF files are not found on the classpath
   */
  private void initSchemaPartition() throws Exception {
    SchemaPartition schemaPartition = service.getSchemaService().getSchemaPartition();

    // Init the LdifPartition
    LdifPartition ldifPartition = new LdifPartition();
    String workingDirectory = service.getWorkingDirectory().getPath();
    ldifPartition.setWorkingDirectory(workingDirectory + "/schema");

    // Extract the schema on disk (a brand new one) and load the registries
    File schemaRepository = new File(workingDirectory, "schema");
    SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(new File(workingDirectory));
    extractor.extractOrCopy(true);

    schemaPartition.setWrappedPartition(ldifPartition);

    SchemaLoader loader = new LdifSchemaLoader(schemaRepository);
    SchemaManager schemaManager = new DefaultSchemaManager(loader);
    service.setSchemaManager(schemaManager);

    // We have to load the schema now, otherwise we won't be able
    // to initialize the Partitions, as we won't be able to parse
    // and normalize their suffix DN
    schemaManager.loadAllEnabled();

    schemaPartition.setSchemaManager(schemaManager);

    List<Throwable> errors = schemaManager.getErrors();

    if (errors.size() != 0) {
      throw new Exception(MessageFormat.format(c_ResourceBundle.getString("schema.load.failed"), errors));
    }
  }//initSchemaPartition


  /**
   * Initialize the server. It creates the partition, adds the index, and
   * injects the context entries for the created partitions.
   *
   * @param workDir the directory to be used for storing the data
   * @throws Exception if there were some problems while initializing the system
   */
  private void initDirectoryService(File workDir) throws Exception {
    // Initialize the LDAP service
    service = new DefaultDirectoryService();
    service.setWorkingDirectory(workDir);

    // first load the schema
    initSchemaPartition();

    // then the system partition
    // this is a MANDATORY partition
    Partition systemPartition = addPartition("system", ServerDNConstants.SYSTEM_DN);
    service.setSystemPartition(systemPartition);

    // Disable the ChangeLog system
    service.getChangeLog().setEnabled(false);
    service.setDenormalizeOpAttrsEnabled(true);

    //Disable Anoymous Access
    //service.setAccessControlEnabled(true);
    service.setAllowAnonymousAccess(false);

    log.debug("" + service.getInterceptor("org.apache.directory.server.core.authn.AuthenticationInterceptor"));
    AuthenticationInterceptor ai = (AuthenticationInterceptor) service.getInterceptor("org.apache.directory.server.core.authn.AuthenticationInterceptor");
    Set<Authenticator> auths = new HashSet<Authenticator>();
    auths.add(new CrowdAuthenticator(m_CrowdClient));
    ai.setAuthenticators(auths);

    // Add Crowd Partition
    addCrowdPartition("crowd", "dc=crowd");

    // And start the service
    service.startup();
  }//initDirectoryService

  /**
   * Starts the LdapServer
   *
   * @param srvConfig server configuration as properties.
   * @throws Exception if starting the LDAP server does not work.
   */
  public void startServer(Properties srvConfig) throws Exception {
    server = new LdapServer();
    int serverPort = Integer.parseInt(srvConfig.getProperty(CONFIG_KEY_PORT,"10389"));

    Transport t = new TcpTransport(serverPort);

    boolean sslEnabled = Boolean.parseBoolean(srvConfig.getProperty(CONFIG_KEY_SSLENABLE,"false"));

    if(sslEnabled) {
      String keyStore = srvConfig.getProperty(CONFIG_KEY_KEYSTORE,"etc/crowd-ldap-server.keystore");
      String password = srvConfig.getProperty(CONFIG_KEY_CERTIFICATEPASSWD,"changeit");

      t.setEnableSSL(true);
      server.setKeystoreFile(keyStore);
      server.setCertificatePassword(password);
      server.addExtendedOperationHandler(new StartTlsHandler());

    }
    server.setTransports(t);
    server.setDirectoryService(service);
    server.start();
  }//startServer


  /**
   * Main application method.
   *
   * @param args not used.
   */
  public static void main(String[] args) {
    try {

      File confDir = new File("etc");

      // Configure Logging
      Properties logConfig = new Properties();
      File f1 = new File(confDir, "log4j.properties");
      logConfig.load(new FileReader(f1));
      PropertyConfigurator.configure(logConfig);

      log.info(MessageFormat.format(c_ResourceBundle.getString("configuration.directory"), confDir.getAbsolutePath()));

      // Server Configuration
      Properties serverConfig = new Properties();
      File f2 = new File(confDir, "crowd-ldap-server.properties");
      serverConfig.load(new FileReader(f2));

      log.info(c_ResourceBundle.getString("starting.up.crowdldap.server"));
      File workDir = new File("work");
      workDir.mkdirs();
      log.info(MessageFormat.format(c_ResourceBundle.getString("working.directory"), workDir.getAbsolutePath()));

      // Create the server
      CrowdLDAPServer clds = new CrowdLDAPServer(workDir, confDir);

      // Start the server
      clds.startServer(serverConfig);
      log.info(c_ResourceBundle.getString("starting.directory.listener"));
    } catch (Exception e) {
      log.error("main()", e);
    }
  }//main


  private static final String CONFIG_KEY_PORT = "listener.port";
  private static final String CONFIG_KEY_SSLENABLE = "ssl.enabled";

  private static final String CONFIG_KEY_KEYSTORE = "ssl.keystore";
  private static final String CONFIG_KEY_CERTIFICATEPASSWD = "ssl.certificate.password";

}//class CrowdLDAPServer
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
import org.apache.commons.collections.iterators.ArrayListIterator;
import org.apache.commons.io.FileUtils;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.DnFactory;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.authn.Authenticator;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.core.shared.DefaultDnFactory;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.directory.server.xdbm.Index;
import org.apache.log4j.PropertyConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
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

  //Server Configuration
  private Properties m_ServerConfig;
  //Directory Service
  private DirectoryService service;
  //LDAP Server
  private LdapServer server;
  //Crowd Configuration
  private Properties m_CrowdConfig;
  private CrowdClient m_CrowdClient;
  //AD memberOf Emulation
  private boolean m_emulateADmemberOf = false;
  private boolean m_includeNested = false;

  private File workDir = null;
 
  /**
   * Creates a new instance of the  CrowdLDAPServer.
   * Loads the configuration and prepares the Crowd Client side.
   *
   * @param workDir the working directory.
   * @param confDir the configuration directory.	
   * @param serverConfig server configuration as properties.
   * @throws Exception if configuration loading or crowd client setup did not work.
   */
  public CrowdLDAPServer(File workDir, File confDir, Properties serverConfig) throws Exception {
      this.workDir = workDir;

      try {
      m_ServerConfig = serverConfig;
      m_emulateADmemberOf = Boolean.parseBoolean(m_ServerConfig.getProperty(CONFIG_KEY_EMULATE_MEMBEROF, "false"));
	  m_includeNested = Boolean.parseBoolean(m_ServerConfig.getProperty(CONFIG_KEY_INCLUDE_NESTED, "false"));

      log.debug(c_ResourceBundle.getString("loading.configuration"));
      m_CrowdConfig = new Properties();
      File f = new File(confDir, "crowd.properties");
      m_CrowdConfig.load(new FileReader(f));
      initCrowdClient();
    } catch (Exception ex) {
      log.error("CrowdLDAPServer(File,File)", ex);
    }


      this.createNewLoaders();

        initDirectoryService();
  }//CrowdLDAPServer


    public void createNewLoaders() throws IOException {
        // Extract the schema on disk (a brand new one) and load the registries
        SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(workDir);
        extractor.extractOrCopy(true);

        File attributeTypesDir = new File(workDir, "schema/ou=schema/cn=other/ou=attributetypes");
        attributeTypesDir.mkdirs();

        // memberOf Support
        if(m_emulateADmemberOf) {
            File memberOfLDIF = new File(attributeTypesDir, "m-oid=1.2.840.113556.1.2.102.ldif");
            if(!memberOfLDIF.exists()) {
                InputStream in = null;
                OutputStream out = null;
                try {
                    in = getClass().getClassLoader().getResourceAsStream("net/wimpi/crowd/ldap/memberof.ldif");
                    out = new FileOutputStream(memberOfLDIF);

                    // Transfer bytes from in to out
                    byte[] buf = new byte[1024];
                    int len;
                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }
                } finally {
                    if(in != null) {
                        in.close();
                    }
                    if(out != null) {
                        out.close();
                    }
                }
            }
        }

        File rf2307bisSchemaDir = new File(workDir, "schema/ou=schema/cn=rfc2307bis/ou=attributetypes");
        rf2307bisSchemaDir.mkdirs();

        ArrayList<String> filenames = new ArrayList<String>();
        filenames.add("m-oid=1.3.6.1.1.1.1.0");
        filenames.add("m-oid=1.3.6.1.1.1.1.1");


        for (String name : filenames) {
            File rf2307bisSchema = new File(attributeTypesDir, name +".ldif");
            if(!rf2307bisSchema.exists()) {
                InputStream in = null;
                OutputStream out = null;
                try {
                    in = getClass().getClassLoader().getResourceAsStream("net/wimpi/crowd/ldap/rfc2307/" + name + ".ldif");
                    out = new FileOutputStream(rf2307bisSchema);

                    // Transfer bytes from in to out
                    byte[] buf = new byte[1024];
                    int len;
                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }
                } finally {
                    if(in != null) {
                        in.close();
                    }
                    if(out != null) {
                        out.close();
                    }
                }
            }
        }





    }


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
   * initialize the schema manager and add the schema partition to diectory service
   *
   * @throws Exception if the schema LDIF files are not found on the classpath
   */
  private void initSchemaPartition() throws Exception {
      File schemaRepository = new File(workDir, "schema");

      SchemaLoader loader = new LdifSchemaLoader(schemaRepository);
      SchemaManager schemaManager = new DefaultSchemaManager(loader);
      schemaManager.loadAllEnabled();
      service.setSchemaManager(schemaManager);


      SchemaPartition schemaPartition = new SchemaPartition(schemaManager);
      service.setSchemaPartition(schemaPartition);


      // Init the LdifPartition
      LdifPartition ldifPartition = new LdifPartition(service.getSchemaManager(), service.getDnFactory());
      ldifPartition.setPartitionPath(schemaRepository.toURI());

      schemaPartition.setWrappedPartition(ldifPartition);
      service.setInstanceLayout(new InstanceLayout(this.workDir));


      // We have to load the schema now, otherwise we won't be able
      // to initialize the Partitions, as we won't be able to parse
      // and normalize their suffix DN
      schemaManager.loadAllEnabled();



      List<Throwable> errors = schemaManager.getErrors();

      if (errors.size() != 0) {
          throw new Exception(MessageFormat.format(c_ResourceBundle.getString("schema.load.failed"), errors));
      }
  }//initSchemaPartition


  /**
   * Initialize the server. It creates the partition, adds the index, and
   * injects the context entries for the created partitions.
   *
   * @throws Exception if there were some problems while initializing the system
   */
  private void initDirectoryService() throws Exception {
    // Initialize the LDAP service
    service = new DefaultDirectoryService();


    // first load the schema
    initSchemaPartition();

    // then the system partition
    // this is a MANDATORY partition

    JdbmPartition partition = new JdbmPartition(service.getSchemaManager(), service.getDnFactory());
    partition.setId("system");
    partition.setPartitionPath(new File(this.workDir, "system").toURI());
    partition.setSuffixDn(new Dn(ServerDNConstants.SYSTEM_DN));

    service.setSystemPartition(partition);

    // Disable the ChangeLog system
    service.getChangeLog().setEnabled(false);
    service.setDenormalizeOpAttrsEnabled(false);


    //Disable Anoymous Access
    //service.setAccessControlEnabled(true);
    service.setAllowAnonymousAccess(false);

    List<Interceptor> interceptors = service.getInterceptors();

      for (Interceptor interceptor : interceptors) {
          if (interceptor instanceof  AuthenticationInterceptor) {
              log.debug("" + interceptor.getName());
              AuthenticationInterceptor ai = (AuthenticationInterceptor) interceptor;
              Set<Authenticator> auths = new HashSet<Authenticator>();
              auths.add(new CrowdAuthenticator(m_CrowdClient, service));
              ai.setAuthenticators(auths);
          }
      }

    // Add Crowd Partition
    addCrowdPartition("crowd", "dc=crowd");

    // And start the service
    service.startup();
  }//initDirectoryService

  /**
   * Starts the LdapServer
   *
   * @throws Exception if starting the LDAP server does not work.
   */
  public void startServer() throws Exception {
    server = new LdapServer();
    int serverPort = Integer.parseInt(m_ServerConfig.getProperty(CONFIG_KEY_PORT,"10389"));

    Transport t = new TcpTransport(serverPort);

    //SSL Support
    boolean sslEnabled = Boolean.parseBoolean(m_ServerConfig.getProperty(CONFIG_KEY_SSLENABLE,"false"));

    if(sslEnabled) {
      String keyStore = m_ServerConfig.getProperty(CONFIG_KEY_KEYSTORE,"etc/crowd-ldap-server.keystore");
      String password = m_ServerConfig.getProperty(CONFIG_KEY_CERTIFICATEPASSWD,"changeit");

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
     * Add a new partition to the server.
     *
     * @param partitionId The partition Id
     * @param partitionDn The partition DN
     * @return The newly added partition
     * @throws Exception If the partition can't be added
     */
    private Partition addCrowdPartition(String partitionId, String partitionDn) throws Exception {
        // Create a new partition named 'foo'.
        CrowdPartition partition = new CrowdPartition(m_CrowdClient, m_emulateADmemberOf, m_includeNested);
        partition.setId(partitionId);
        partition.setSuffix(partitionDn);
        partition.setSchemaManager(service.getSchemaManager());
        partition.initialize();
        service.addPartition(partition);

        return partition;
    }//addCrowdPartition

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
      if(workDir.exists()) {
          FileUtils.deleteDirectory(workDir);
      }
      workDir.mkdirs();
      log.info(MessageFormat.format(c_ResourceBundle.getString("working.directory"), workDir.getAbsolutePath()));

      // Create the server
      CrowdLDAPServer clds = new CrowdLDAPServer(workDir, confDir, serverConfig);

      // Start the server
      clds.startServer();
      log.info(c_ResourceBundle.getString("starting.directory.listener"));
    } catch (Exception e) {
      log.error("main()", e);
    }
  }//main


  private static final String CONFIG_KEY_PORT = "listener.port";
  private static final String CONFIG_KEY_SSLENABLE = "ssl.enabled";

  private static final String CONFIG_KEY_KEYSTORE = "ssl.keystore";
  private static final String CONFIG_KEY_CERTIFICATEPASSWD = "ssl.certificate.password";
  
  private static final String CONFIG_KEY_EMULATE_MEMBEROF = "emulate.ad.memberof";  
  private static final String CONFIG_KEY_INCLUDE_NESTED = "emulate.ad.include.nested";  

}//class CrowdLDAPServer
//
//   Copyright 2016  Cityzen Data
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

package io.warp10.geode;

import com.google.common.base.Preconditions;

import io.warp10.Revision;
import io.warp10.WarpConfig;
import io.warp10.WarpDist;
import io.warp10.continuum.Configuration;
import io.warp10.continuum.JettyUtil;
import io.warp10.continuum.ThrottlingManager;
import io.warp10.continuum.egress.CORSHandler;
import io.warp10.continuum.egress.EgressExecHandler;
import io.warp10.continuum.egress.EgressFetchHandler;
import io.warp10.continuum.egress.EgressFindHandler;
import io.warp10.continuum.egress.EgressMobiusHandler;
import io.warp10.continuum.ingress.DatalogForwarder;
import io.warp10.continuum.sensision.SensisionConstants;
import io.warp10.continuum.store.Constants;
import io.warp10.continuum.store.StoreClient;
import io.warp10.crypto.CryptoUtils;
import io.warp10.crypto.KeyStore;
import io.warp10.crypto.OSSKeyStore;
import io.warp10.crypto.UnsecureKeyStore;
import io.warp10.quasar.filter.QuasarTokenFilter;
import io.warp10.script.ScriptRunner;
import io.warp10.script.WarpScriptLib;
import io.warp10.sensision.Sensision;
import io.warp10.standalone.NullDirectoryClient;
import io.warp10.standalone.NullStoreClient;
import io.warp10.standalone.PlasmaStoreClient;
import io.warp10.standalone.StandaloneChunkedMemoryStore;
import io.warp10.standalone.StandaloneDeleteHandler;
import io.warp10.standalone.StandaloneDirectoryClient;
import io.warp10.standalone.StandaloneGeoDirectory;
import io.warp10.standalone.StandaloneIngressHandler;
import io.warp10.standalone.StandaloneMemoryStore;
import io.warp10.standalone.StandalonePlasmaHandler;
import io.warp10.standalone.StandaloneScriptRunner;
import io.warp10.standalone.StandaloneStreamUpdateHandler;
import io.warp10.warp.sdk.AbstractWarp10Plugin;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlets.gzip.GzipHandler;
import org.fusesource.leveldbjni.JniDBFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class WarpGeode extends WarpDist implements Runnable {

  private static final String NULL = "null";

  private static boolean standaloneMode = false;

  private static int port;

  private static String host;

  private static final String[] REQUIRED_PROPERTIES = {
    Configuration.STANDALONE_PORT,
    Configuration.STANDALONE_ACCEPTORS,
    Configuration.STANDALONE_SELECTORS,
    Configuration.INGRESS_WEBSOCKET_MAXMESSAGESIZE,
    Configuration.PLASMA_FRONTEND_WEBSOCKET_MAXMESSAGESIZE,
    Configuration.WARP_HASH_CLASS,
    Configuration.WARP_HASH_LABELS,
    Configuration.CONTINUUM_HASH_INDEX,
    Configuration.WARP_HASH_TOKEN,
    Configuration.WARP_HASH_APP,
    Configuration.WARP_AES_TOKEN,
    Configuration.WARP_AES_SCRIPTS,
    Configuration.CONFIG_WARPSCRIPT_UPDATE_ENDPOINT,
    Configuration.CONFIG_WARPSCRIPT_META_ENDPOINT,
    Configuration.WARP_TIME_UNITS,
  };

  public WarpGeode() {
    // TODO Auto-generated constructor stub
  }
  
  public static void main(String[] args) throws Exception {
    
    System.setProperty("java.awt.headless", "true");
    
    System.out.println();
    System.out.println(Constants.WARP10_BANNER);
    System.out.println("  Revision " + Revision.REVISION);
    System.out.println();

    Map<String,String> labels = new HashMap<String, String>();
    labels.put(SensisionConstants.SENSISION_LABEL_COMPONENT, "standalone");
    Sensision.set(SensisionConstants.SENSISION_CLASS_WARP_REVISION, labels, Revision.REVISION);

    setProperties(args[0]);
    
    boolean nullbackend = "true".equals(WarpConfig.getProperties().getProperty(NULL));
    
    boolean plasmabackend = "true".equals(WarpConfig.getProperties().getProperty(Configuration.PURE_PLASMA));
    
    boolean inmemory = "true".equals(WarpConfig.getProperties().getProperty(Configuration.IN_MEMORY));

    Properties properties = getProperties();
    
    for (String property: REQUIRED_PROPERTIES) {
      // Don't check LEVELDB_HOME when in-memory
      if (inmemory && Configuration.LEVELDB_HOME.equals(property)) {
        continue;
      }
      Preconditions.checkNotNull(properties.getProperty(property), "Property '" + property + "' MUST be set.");
    }

    //
    // Initialize KeyStore
    //

    KeyStore keystore;
    
    if (properties.containsKey(Configuration.OSS_MASTER_KEY)) {
      keystore = new OSSKeyStore(properties.getProperty(Configuration.OSS_MASTER_KEY));
    } else {
      keystore = new UnsecureKeyStore();
    }

    extractKeys(keystore, properties);
    
    keystore.setKey(KeyStore.SIPHASH_CLASS, keystore.decodeKey(properties.getProperty(Configuration.WARP_HASH_CLASS)));
    Preconditions.checkArgument(16 == keystore.getKey(KeyStore.SIPHASH_CLASS).length, Configuration.WARP_HASH_CLASS + " MUST be 128 bits long.");
    keystore.setKey(KeyStore.SIPHASH_LABELS, keystore.decodeKey(properties.getProperty(Configuration.WARP_HASH_LABELS)));
    Preconditions.checkArgument(16 == keystore.getKey(KeyStore.SIPHASH_LABELS).length, Configuration.WARP_HASH_LABELS + " MUST be 128 bits long.");
    
    //
    // Generate secondary keys. We use the ones' complement of the primary keys
    //
    
    keystore.setKey(KeyStore.SIPHASH_CLASS_SECONDARY, CryptoUtils.invert(keystore.getKey(KeyStore.SIPHASH_CLASS)));
    keystore.setKey(KeyStore.SIPHASH_LABELS_SECONDARY, CryptoUtils.invert(keystore.getKey(KeyStore.SIPHASH_LABELS)));        
    
    keystore.setKey(KeyStore.SIPHASH_INDEX, keystore.decodeKey(properties.getProperty(Configuration.CONTINUUM_HASH_INDEX)));
    Preconditions.checkArgument(16 == keystore.getKey(KeyStore.SIPHASH_INDEX).length, Configuration.CONTINUUM_HASH_INDEX + " MUST be 128 bits long.");
    keystore.setKey(KeyStore.SIPHASH_TOKEN, keystore.decodeKey(properties.getProperty(Configuration.WARP_HASH_TOKEN)));
    Preconditions.checkArgument(16 == keystore.getKey(KeyStore.SIPHASH_TOKEN).length, Configuration.WARP_HASH_TOKEN + " MUST be 128 bits long.");
    keystore.setKey(KeyStore.SIPHASH_APPID, keystore.decodeKey(properties.getProperty(Configuration.WARP_HASH_APP)));
    Preconditions.checkArgument(16 == keystore.getKey(KeyStore.SIPHASH_APPID).length, Configuration.WARP_HASH_APP + " MUST be 128 bits long.");
    keystore.setKey(KeyStore.AES_TOKEN, keystore.decodeKey(properties.getProperty(Configuration.WARP_AES_TOKEN)));
    Preconditions.checkArgument((16 == keystore.getKey(KeyStore.AES_TOKEN).length) || (24 == keystore.getKey(KeyStore.AES_TOKEN).length) || (32 == keystore.getKey(KeyStore.AES_TOKEN).length), Configuration.WARP_AES_TOKEN + " MUST be 128, 192 or 256 bits long.");
    keystore.setKey(KeyStore.AES_SECURESCRIPTS, keystore.decodeKey(properties.getProperty(Configuration.WARP_AES_SCRIPTS)));
    Preconditions.checkArgument((16 == keystore.getKey(KeyStore.AES_SECURESCRIPTS).length) || (24 == keystore.getKey(KeyStore.AES_SECURESCRIPTS).length) || (32 == keystore.getKey(KeyStore.AES_SECURESCRIPTS).length), Configuration.WARP_AES_SCRIPTS + " MUST be 128, 192 or 256 bits long.");

    if (properties.containsKey(Configuration.WARP_AES_METASETS)) {
      keystore.setKey(KeyStore.AES_METASETS, keystore.decodeKey(properties.getProperty(Configuration.WARP_AES_METASETS)));
      Preconditions.checkArgument((16 == keystore.getKey(KeyStore.AES_METASETS).length) || (24 == keystore.getKey(KeyStore.AES_METASETS).length) || (32 == keystore.getKey(KeyStore.AES_METASETS).length), Configuration.WARP_AES_METASETS + " MUST be 128, 192 or 256 bits long.");
    }

    if (null != properties.getProperty(Configuration.WARP_AES_LOGGING, Configuration.WARP_DEFAULT_AES_LOGGING)) {
      keystore.setKey(KeyStore.AES_LOGGING, keystore.decodeKey(properties.getProperty(Configuration.WARP_AES_LOGGING, Configuration.WARP_DEFAULT_AES_LOGGING)));
      Preconditions.checkArgument((16 == keystore.getKey(KeyStore.AES_LOGGING).length) || (24 == keystore.getKey(KeyStore.AES_LOGGING).length) || (32 == keystore.getKey(KeyStore.AES_LOGGING).length), Configuration.WARP_AES_LOGGING + " MUST be 128, 192 or 256 bits long.");      
    }
    
    setKeyStore(keystore);

    // Register shutdown hook to close the DB.
    Runtime.getRuntime().addShutdownHook(new Thread(new WarpGeode()));
    
    WarpScriptLib.registerExtensions();

    //
    // Initialize ThrottlingManager
    //
    
    ThrottlingManager.init();

    //
    // Create Jetty server
    //
    
    Server server = new Server();

    int acceptors = Integer.valueOf(properties.getProperty(Configuration.STANDALONE_ACCEPTORS));
    int selectors = Integer.valueOf(properties.getProperty(Configuration.STANDALONE_SELECTORS));
    port = Integer.valueOf(properties.getProperty(Configuration.STANDALONE_PORT));
    host = properties.getProperty(Configuration.STANDALONE_HOST);
    
    ServerConnector connector = new ServerConnector(server, acceptors, selectors);

    connector.setPort(port);
    
    if (null != host) {
      connector.setHost(host);
    }
    
    String idle = properties.getProperty(Configuration.STANDALONE_IDLE_TIMEOUT);
    
    if (null != idle) {
      connector.setIdleTimeout(Long.parseLong(idle));
    }
    
    connector.setName("Continuum Standalone Egress");
    
    server.setConnectors(new Connector[] { connector });

    HandlerList handlers = new HandlerList();
    
    Handler cors = new CORSHandler();
    handlers.addHandler(cors);
    
    GeodeDirectoryClient sdc = null;
    StoreClient scc = null;

    if (inmemory) {
      sdc = new GeodeDirectoryClient(keystore);
      scc = new GeodeMemoryStore(keystore,
          Long.valueOf(WarpDist.getProperties().getProperty(Configuration.IN_MEMORY_DEPTH, Long.toString(60 * 60 * 1000 * Constants.TIME_UNITS_PER_MS))),
          Long.valueOf(WarpDist.getProperties().getProperty(Configuration.IN_MEMORY_HIGHWATERMARK, "100000")),
          Long.valueOf(WarpDist.getProperties().getProperty(Configuration.IN_MEMORY_LOWWATERMARK, "80000")));
      ((GeodeMemoryStore) scc).setDirectoryClient(sdc);
      if ("true".equals(WarpDist.getProperties().getProperty(Configuration.IN_MEMORY_EPHEMERAL))) {
        ((GeodeMemoryStore) scc).setEphemeral(true);
      }
      ((GeodeMemoryStore) scc).load();
    }
        
    GeodeGeoDirectory geodir = new GeodeGeoDirectory(keystore.clone(), scc, sdc, properties);
    
    if (properties.containsKey(Configuration.RUNNER_ROOT)) {
      if (!properties.containsKey(Configuration.RUNNER_ENDPOINT)) {
        properties.setProperty(Configuration.RUNNER_ENDPOINT, "");
        StandaloneScriptRunner runner = new StandaloneScriptRunner(properties, keystore.clone(), scc, sdc,  geodir, properties);
      } else {
        //
        // Allocate a normal runner
        //
        ScriptRunner runner = new ScriptRunner(keystore.clone(), properties);
      }
    }
    
    //
    // Start the Datalog Forwarder
    //
    
    if (properties.containsKey(Configuration.DATALOG_FORWARDER_SRCDIR) && properties.containsKey(Configuration.DATALOG_FORWARDER_DSTDIR)) {
      DatalogForwarder forwarder = new DatalogForwarder(keystore, properties);
    }
    
    //
    // Enable the ThrottlingManager (not 
    //
    
    ThrottlingManager.enable();
    
    QuasarTokenFilter tf = new QuasarTokenFilter(properties, keystore);
    
    GzipHandler gzip = new GzipHandler();
    EgressExecHandler egressExecHandler = new EgressExecHandler(keystore, properties, sdc, geodir.getClient(), scc); 
    gzip.setHandler(egressExecHandler);
    gzip.setBufferSize(65536);
    gzip.setMinGzipSize(0);
    handlers.addHandler(gzip);
    setEgress(true);

    gzip = new GzipHandler();
    gzip.setHandler(new GeodeIngressHandler(keystore, sdc, scc));
    gzip.setBufferSize(65536);
    gzip.setMinGzipSize(0);
    handlers.addHandler(gzip);

    gzip = new GzipHandler();
    gzip.setHandler(new EgressFetchHandler(keystore, properties, sdc, scc));
    gzip.setBufferSize(65536);
    gzip.setMinGzipSize(0);
    handlers.addHandler(gzip);

    gzip = new GzipHandler();
    gzip.setHandler(new EgressFindHandler(keystore, sdc));
    gzip.setBufferSize(65536);
    gzip.setMinGzipSize(0);
    handlers.addHandler(gzip);

    gzip = new GzipHandler();
    gzip.setHandler(new GeodeIngressHandler(keystore, sdc, scc));
    gzip.setBufferSize(65536);
    gzip.setMinGzipSize(0);
    handlers.addHandler(gzip);
    
    handlers.addHandler(geodir);    

    //ContextHandler context = new ContextHandler();
    StandalonePlasmaHandler plasmaHandler = new StandalonePlasmaHandler(keystore, properties, sdc);
    scc.addPlasmaHandler(plasmaHandler);  
    scc.addPlasmaHandler(geodir);
    
    //context.setHandler(plasmaHandler);
    //handlers.addHandler(context);
    handlers.addHandler(plasmaHandler);
    
    //StandaloneStreamUpdateHandler streamUpdateHandler = new StandaloneStreamUpdateHandler(keystore, properties, sdc, scc);
    //handlers.addHandler(streamUpdateHandler);

    EgressMobiusHandler mobiusHandler = new EgressMobiusHandler(scc, sdc, properties);
    handlers.addHandler(mobiusHandler);

    server.setHandler(handlers);
        
    JettyUtil.setSendServerVersion(server, false);
    
    // Clear master key from memory
    keystore.forget();

    //
    // Register the plugins after we've cleared the master key
    //
    
    AbstractWarp10Plugin.registerPlugins();

    try {
      System.out.println("#### standalone.endpoint " + InetAddress.getByName(host) + ":" + port);
      server.start();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    
    // Retrieve actual local port
    port = connector.getLocalPort();

    // Indicate standalone mode is on
    standaloneMode = true;

    WarpDist.setInitialized(true);
    
    try {
      while(true) {
        try {
          Thread.sleep(60000L);
        } catch (InterruptedException ie) {        
        }
      }      
    } catch (Throwable t) {
      System.err.println(t.getMessage());
      server.stop();
    }
  }
  
  public static boolean isStandaloneMode() {
    return standaloneMode;
  }
  
  public static int getPort() {
    return port;
  }
  
  public static String getHost() {
    return host;
  }
  
  @Override
  public void run() {
    //disconnect from geode
  }
  
  /**
   * Extract Ingress related keys and populate the KeyStore with them.
   * 
   * @param props Properties from which to extract the key specs
   */
  private static void extractKeys(KeyStore keystore, Properties props) {
    String keyspec = props.getProperty(Configuration.LEVELDB_METADATA_AES);
    
    if (null != keyspec) {
      byte[] key = keystore.decodeKey(keyspec);
      Preconditions.checkArgument(16 == key.length || 24 == key.length || 32 == key.length, "Key " + Configuration.LEVELDB_METADATA_AES + " MUST be 128, 192 or 256 bits long.");
      keystore.setKey(KeyStore.AES_LEVELDB_METADATA, key);
    }
    
    keyspec = props.getProperty(Configuration.LEVELDB_DATA_AES);
    
    if (null != keyspec) {
      byte[] key = keystore.decodeKey(keyspec);
      Preconditions.checkArgument(16 == key.length || 24 == key.length || 32 == key.length, "Key " + Configuration.LEVELDB_DATA_AES + " MUST be 128, 192 or 256 bits long.");
      keystore.setKey(KeyStore.AES_LEVELDB_DATA, key);
    }
    
    keyspec = props.getProperty(Configuration.LEVELDB_INDEX_AES);
    
    if (null != keyspec) {
      byte[] key = keystore.decodeKey(keyspec);
      Preconditions.checkArgument(16 == key.length || 24 == key.length || 32 == key.length, "Key " + Configuration.LEVELDB_INDEX_AES + " MUST be 128, 192 or 256 bits long.");
      keystore.setKey(KeyStore.AES_LEVELDB_INDEX, key);
    }
    
    if (null != props.getProperty(Configuration.CONFIG_FETCH_PSK)) {
      keystore.setKey(KeyStore.SIPHASH_FETCH_PSK, keystore.decodeKey(props.getProperty(Configuration.CONFIG_FETCH_PSK)));
      Preconditions.checkArgument((16 == keystore.getKey(KeyStore.SIPHASH_FETCH_PSK).length), Configuration.CONFIG_FETCH_PSK + " MUST be 128 bits long.");            
    }

  }
}
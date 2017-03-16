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

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.MapMaker;

import io.warp10.SmartPattern;
import io.warp10.WarpConfig;
import io.warp10.continuum.Configuration;
import io.warp10.continuum.gts.GTSHelper;
import io.warp10.continuum.sensision.SensisionConstants;
import io.warp10.continuum.store.Constants;
import io.warp10.continuum.store.DirectoryClient;
import io.warp10.continuum.store.MetadataIterator;
import io.warp10.continuum.store.thrift.data.Metadata;
import io.warp10.crypto.KeyStore;
import io.warp10.crypto.SipHashInline;
import io.warp10.sensision.Sensision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;;
import java.util.regex.Pattern;

public class GeodeDirectoryClient implements DirectoryClient {

  private static final Logger LOG = LoggerFactory.getLogger(GeodeDirectoryClient.class);

  private static final String DIRECTORY_INIT_NTHREADS_DEFAULT = "4";

  private static final byte[] METADATA_PREFIX = "M".getBytes(Charsets.US_ASCII);

  private static final int MAX_BATCH_SIZE = 500000;

  private final KeyStore keystore;

  private final byte[] classKey;
  private final byte[] labelsKey;

  private final long[] classLongs;
  private final long[] labelsLongs;

  private final byte[] aesKey;

  private final int initNThreads;

  /**
   * Maps of class name to labelsId to metadata
   */
  // 128BITS
  private static final Map<String,Map<Long,Metadata>> metadatas = new MapMaker().concurrencyLevel(64).makeMap();
  private static final Map<BigInteger,Metadata> metadatasById = new MapMaker().concurrencyLevel(64).makeMap();

  public GeodeDirectoryClient(final KeyStore keystore) {

    this.initNThreads = Integer.parseInt(WarpConfig.getProperties().getProperty(Configuration.DIRECTORY_INIT_NTHREADS, DIRECTORY_INIT_NTHREADS_DEFAULT));

    this.keystore = keystore;
  
    this.aesKey = this.keystore.getKey(KeyStore.AES_LEVELDB_METADATA);
    this.classKey = this.keystore.getKey(KeyStore.SIPHASH_CLASS);
    this.classLongs = SipHashInline.getKey(this.classKey);
    
    this.labelsKey = this.keystore.getKey(KeyStore.SIPHASH_LABELS);
    this.labelsLongs = SipHashInline.getKey(this.labelsKey);
  }
  
  public List<Metadata> find(List<String> classExpr, List<Map<String,String>> labelsExpr) {
    
    //
    // Build patterns from expressions
    //
    
    SmartPattern classSmartPattern;
    
    Collection<Metadata> metadatas;
    
    if (classExpr.size() > 1) {
      metadatas = new HashSet<Metadata>();
    } else {
      metadatas = new ArrayList<Metadata>();
    }

    Set<String> classNames = null;
    
    for (int i = 0; i < classExpr.size(); i++) {
      
      String exactClassName = null;
      
      if (classExpr.get(i).startsWith("=") || !classExpr.get(i).startsWith("~")) {
        exactClassName = classExpr.get(i).startsWith("=") ? classExpr.get(i).substring(1) : classExpr.get(i);
        classSmartPattern = new SmartPattern(exactClassName);
      } else {
        classSmartPattern = new SmartPattern(Pattern.compile(classExpr.get(i).substring(1)));
      }
      
      Map<String,SmartPattern> labelPatterns = new HashMap<String,SmartPattern>();
      
      if (null != labelsExpr.get(i)) {
        for (Entry<String,String> entry: labelsExpr.get(i).entrySet()) {
          String label = entry.getKey();
          String expr = entry.getValue();
          Pattern pattern;
          
          if (expr.startsWith("=") || !expr.startsWith("~")) {
            labelPatterns.put(label, new SmartPattern(expr.startsWith("=") ? expr.substring(1) : expr));
          } else {
            pattern = Pattern.compile(expr.substring(1));
            labelPatterns.put(label,  new SmartPattern(pattern));
          }          
        }      
      }
             
      if (null != exactClassName) {
        if (!this.metadatas.containsKey(exactClassName)) {
          continue;
        }
        classNames = new HashSet<String>();
        classNames.add(exactClassName);
      } else {
        classNames = this.metadatas.keySet();
      }

      //
      // Create arrays to check the labels, this is to speed up discard
      //
      
      List<String> labelNames = new ArrayList<String>(labelPatterns.size());
      List<SmartPattern> labelSmartPatterns = new ArrayList<SmartPattern>(labelPatterns.size());
      String[] labelValues = null;
      
      //
      // Put producer/app/owner first
      //
      
      if (labelPatterns.containsKey(Constants.PRODUCER_LABEL)) {
        labelNames.add(Constants.PRODUCER_LABEL);
        labelSmartPatterns.add(labelPatterns.get(Constants.PRODUCER_LABEL));
        labelPatterns.remove(Constants.PRODUCER_LABEL);
      }
      if (labelPatterns.containsKey(Constants.APPLICATION_LABEL)) {
        labelNames.add(Constants.APPLICATION_LABEL);
        labelSmartPatterns.add(labelPatterns.get(Constants.APPLICATION_LABEL));
        labelPatterns.remove(Constants.APPLICATION_LABEL);
      }
      if (labelPatterns.containsKey(Constants.OWNER_LABEL)) {
        labelNames.add(Constants.OWNER_LABEL);
        labelSmartPatterns.add(labelPatterns.get(Constants.OWNER_LABEL));
        labelPatterns.remove(Constants.OWNER_LABEL);
      }
      
      //
      // Now add the other labels
      //
      
      for(Entry<String,SmartPattern> entry: labelPatterns.entrySet()) {
        labelNames.add(entry.getKey());
        labelSmartPatterns.add(entry.getValue());
      }

      labelValues = new String[labelNames.size()];

      //
      // Loop over the class names to find matches
      //
      
      for (String className: classNames) {
                
        //
        // If class matches, check all labels for matches
        //
        
        if (classSmartPattern.matches(className)) {
          for (Metadata metadata: this.metadatas.get(className).values()) {
            boolean exclude = false;
            
            int idx = 0;
      
            for (String labelName: labelNames) {
              //
              // Immediately exclude metadata which do not contain one of the
              // labels for which we have patterns either in labels or in attributes
              //

              String labelValue = metadata.getLabels().get(labelName);
              
              if (null == labelValue) {
                labelValue = metadata.getAttributes().get(labelName);
                if (null == labelValue) {
                  exclude = true;
                  break;
                }
              }
              
              labelValues[idx++] = labelValue;
            }
            
            // If we did not collect enough label/attribute values, exclude the GTS
            if (idx < labelNames.size()) {
              exclude = true;
            }
            
            if (exclude) {
              continue;
            }
            
            //
            // Check if the label value matches, if not, exclude the GTS
            //
            
            for (int j = 0; j < labelNames.size(); j++) {
              if (!labelSmartPatterns.get(j).matches(labelValues[j])) {
                exclude = true;
                break;
              }
            }
            
            if (exclude) {
              continue;
            }
            
            //
            // We have a match, rebuild metadata
            //
            // FIXME(hbs): include a 'safe' mode to expose the internal Metadata instances?
            //
            
            Metadata meta = new Metadata();
            meta.setName(className);
            meta.setLabels(ImmutableMap.copyOf(metadata.getLabels()));
            meta.setAttributes(ImmutableMap.copyOf(metadata.getAttributes()));
            // 128BITS
            if (metadata.isSetClassId()) {
              meta.setClassId(metadata.getClassId());
            } else {
              meta.setClassId(GTSHelper.classId(classKey, meta.getName()));
            }
            if (metadata.isSetLabelsId()) {
              meta.setLabelsId(metadata.getLabelsId());
            } else {
              meta.setLabelsId(GTSHelper.labelsId(labelsKey, meta.getLabels()));
            }
            
            metadatas.add(meta);
          }
        }
      }      
    }
    
    if (classExpr.size() > 1) {
      List<Metadata> metas = new ArrayList<Metadata>();
      metas.addAll(metadatas);
      return metas;
    } else {
      return (List<Metadata>) metadatas;
    }    
  };
  
  public void register(Metadata metadata) throws IOException {
    
    //
    // If the metadata are not known, register them
    //
        
    if (Configuration.INGRESS_METADATA_SOURCE.equals(metadata.getSource()) && !metadatas.containsKey(metadata.getName())) {
      store(metadata);
    } else if (Configuration.INGRESS_METADATA_SOURCE.equals(metadata.getSource())) {
      // Compute labelsId
      // 128BITS
      long labelsId = GTSHelper.labelsId(this.labelsLongs, metadata.getLabels());
      
      if (!metadatas.get(metadata.getName()).containsKey(labelsId)) {
        store(metadata);
      } else if (!metadatas.get(metadata.getName()).get(labelsId).getLabels().equals(metadata.getLabels())){
        LOG.warn("LabelsId collision under class '" + metadata.getName() + "' " + metadata.getLabels() + " and " + metadatas.get(metadata.getName()).get(labelsId).getLabels());
        Sensision.update(SensisionConstants.CLASS_WARP_DIRECTORY_LABELS_COLLISIONS, Sensision.EMPTY_LABELS, 1);
      }
    } else if (!Configuration.INGRESS_METADATA_SOURCE.equals(metadata.getSource())) {
      //
      // Metadata registration is not from Ingress, this means we can update the value as it comes from the directory service or a metadata update
      //
      
      // When it is a metadata update request, only store the metadata if the GTS is already known
      if (Configuration.INGRESS_METADATA_UPDATE_ENDPOINT.equals(metadata.getSource())) {
        if (metadatas.containsKey(metadata.getName())) {
          // 128BITS
          long labelsId = GTSHelper.labelsId(this.labelsLongs, metadata.getLabels());
          if (metadatas.get(metadata.getName()).containsKey(labelsId)) {
            store(metadata);
          }
        }
      } else {
        store(metadata);
      }
    }
  }
  
  public synchronized void unregister(Metadata metadata) {
    if (!metadatas.containsKey(metadata.getName())) {
      return;
    }
    // 128BITS
    long labelsId = GTSHelper.labelsId(this.labelsLongs, metadata.getLabels());
    if (!metadatas.get(metadata.getName()).containsKey(labelsId)) {
      return;
    }
    metadatas.get(metadata.getName()).remove(labelsId);
    if (metadatas.get(metadata.getName()).isEmpty()) {
      metadatas.remove(metadata.getName());
    }

    // 128BITS
    long classId = GTSHelper.classId(this.classLongs, metadata.getName());

    // Remove Metadata indexed by id
    byte[] idbytes = new byte[16];
    GTSHelper.fillGTSIds(idbytes, 0, classId, labelsId);
    this.metadatasById.remove(new BigInteger(idbytes));
    
    Sensision.update(SensisionConstants.SENSISION_CLASS_CONTINUUM_DIRECTORY_GTS, Sensision.EMPTY_LABELS, -1);
  }
  
  private void store(Metadata metadata) throws IOException {
    // Compute labelsId and classId
    // 128BITS
    long classId = GTSHelper.classId(this.classLongs, metadata.getName());
    long labelsId = GTSHelper.labelsId(this.labelsLongs, metadata.getLabels());
    
    //ByteBuffer bb = ByteBuffer.wrap(new byte[1 + 8 + 8]).order(ByteOrder.BIG_ENDIAN);    
    //bb.put(METADATA_PREFIX);
    //bb.putLong(classId);
    //bb.putLong(labelsId);

    byte[] bytes = new byte[1 + 8 + 8];
    System.arraycopy(METADATA_PREFIX, 0, bytes, 0, METADATA_PREFIX.length);
    
    int idx = METADATA_PREFIX.length;
    
    bytes[idx++] = (byte) ((classId >> 56) & 0xff);
    bytes[idx++] = (byte) ((classId >> 48) & 0xff);
    bytes[idx++] = (byte) ((classId >> 40) & 0xff);
    bytes[idx++] = (byte) ((classId >> 32) & 0xff);
    bytes[idx++] = (byte) ((classId >> 24) & 0xff);
    bytes[idx++] = (byte) ((classId >> 16) & 0xff);
    bytes[idx++] = (byte) ((classId >> 8) & 0xff);
    bytes[idx++] = (byte) (classId & 0xff);

    bytes[idx++] = (byte) ((labelsId >> 56) & 0xff);
    bytes[idx++] = (byte) ((labelsId >> 48) & 0xff);
    bytes[idx++] = (byte) ((labelsId >> 40) & 0xff);
    bytes[idx++] = (byte) ((labelsId >> 32) & 0xff);
    bytes[idx++] = (byte) ((labelsId >> 24) & 0xff);
    bytes[idx++] = (byte) ((labelsId >> 16) & 0xff);
    bytes[idx++] = (byte) ((labelsId >> 8) & 0xff);
    bytes[idx++] = (byte) (labelsId & 0xff);

    metadata.setClassId(classId);
    metadata.setLabelsId(labelsId);
    
    if (null == metadata.getAttributes()) {
      metadata.setAttributes(new HashMap<String,String>());
    }

    synchronized (metadatas) {
      if (!metadatas.containsKey(metadata.getName())) {
        metadatas.put(metadata.getName(), (Map) new MapMaker().concurrencyLevel(64).makeMap());
      }
      if (null == metadatas.get(metadata.getName()).put(labelsId, metadata)) {
        Sensision.update(SensisionConstants.SENSISION_CLASS_CONTINUUM_DIRECTORY_GTS, Sensision.EMPTY_LABELS, 1);
      }
    }
    //
    // Store Metadata under 'id'
    //

    byte[] idbytes = new byte[16];
    GTSHelper.fillGTSIds(idbytes, 0, classId, labelsId);
    BigInteger id = new BigInteger(idbytes);
    this.metadatasById.put(id, metadata);
  }
  
  public Metadata getMetadataById(BigInteger id) {
    return this.metadatasById.get(id);
  }
  
  @Override
  public Map<String,Object> stats(List<String> classSelector, List<Map<String, String>> labelsSelectors) throws IOException {
    throw new IOException("stats is not available in standalone mode.");
  }
  
  @Override
  public MetadataIterator iterator(List<String> classSelector, List<Map<String, String>> labelsSelectors) throws IOException {
    List<Metadata> metadatas = find(classSelector, labelsSelectors);

    final Iterator<Metadata> iter = metadatas.iterator();

    return new MetadataIterator() {
      @Override
      public void close() throws Exception {}
      
      @Override
      public boolean hasNext() { return iter.hasNext(); }
      
      @Override
      public Metadata next() { return iter.next(); }
    };
  }
}

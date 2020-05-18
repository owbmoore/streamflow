/**
 * Copyright 2014 Lockheed Martin Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package streamflow.datastore.mongodb.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientOptions;
import com.mongodb.MongoClientURI;
import com.mongodb.ReadPreference;
import com.mongodb.ServerAddress;
import streamflow.datastore.core.ComponentDao;
import streamflow.datastore.core.FileContentDao;
import streamflow.datastore.core.FrameworkDao;
import streamflow.datastore.core.KafkaDao;
import streamflow.datastore.core.ResourceDao;
import streamflow.datastore.core.ResourceEntryDao;
import streamflow.datastore.core.RoleDao;
import streamflow.datastore.core.SerializationDao;
import streamflow.datastore.core.TopologyDao;
import streamflow.datastore.core.FileInfoDao;
import streamflow.datastore.core.UserDao;
import streamflow.datastore.mongodb.impl.MongoComponentDao;
import streamflow.datastore.mongodb.impl.MongoDiskFileContentDao;
import streamflow.datastore.mongodb.impl.MongoFrameworkDao;
import streamflow.datastore.mongodb.impl.MongoKafkaDao;
import streamflow.datastore.mongodb.impl.MongoResourceEntryDao;
import streamflow.datastore.mongodb.impl.MongoResourceDao;
import streamflow.datastore.mongodb.impl.MongoRoleDao;
import streamflow.datastore.mongodb.impl.MongoSerializationDao;
import streamflow.datastore.mongodb.impl.MongoTopologyDao;
import streamflow.datastore.mongodb.impl.MongoFileInfoDao;
import streamflow.datastore.mongodb.impl.MongoUserDao;
import streamflow.model.config.DatastoreConfig;
import org.mongodb.morphia.Datastore;
import org.mongodb.morphia.Morphia;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

public class MongoDatastoreModule extends AbstractModule {

    public static Logger LOG = LoggerFactory.getLogger(MongoDatastoreModule.class);

    @Override
    protected void configure() {
        LOG.info("Initializing MongoDB Datastore...");

        bind(ComponentDao.class).to(MongoComponentDao.class);
        bind(FileInfoDao.class).to(MongoFileInfoDao.class);
        bind(FrameworkDao.class).to(MongoFrameworkDao.class);
        bind(ResourceEntryDao.class).to(MongoResourceEntryDao.class);
        bind(ResourceDao.class).to(MongoResourceDao.class);
        bind(RoleDao.class).to(MongoRoleDao.class);
        bind(SerializationDao.class).to(MongoSerializationDao.class);
        bind(TopologyDao.class).to(MongoTopologyDao.class);
        bind(UserDao.class).to(MongoUserDao.class);
        bind(FileContentDao.class).to(MongoDiskFileContentDao.class);
        bind(KafkaDao.class).to(MongoKafkaDao.class);
    }
    
    @Provides
    public MongoClient providesMongoClient(DatastoreConfig datastoreConfig) {

        String mongoUri = datastoreConfig.getProperty("uri", String.class);
        if (mongoUri != null) {
            LOG.info("initializing MongoDB using uri: {}", mongoUri);
            MongoClientURI mongoClientURI = new MongoClientURI(mongoUri);
            List<ServerAddress> serverAddresses = mongoClientURI.getHosts().stream().map(ServerAddress::new).collect(toList());
            MongoClientOptions.Builder clientOptions = MongoClientOptions.builder(mongoClientURI.getOptions());
            configureSsl(datastoreConfig, clientOptions);
            return new MongoClient(serverAddresses, clientOptions.build());
        }

        MongoClientOptions.Builder clientOptions = MongoClientOptions.builder();

        String serverAddressHost = datastoreConfig.getProperty("host", String.class);
        if (serverAddressHost == null) {
            serverAddressHost = "localhost";
        }

        Integer serverAddressPort = datastoreConfig.getProperty("port", Integer.class);
        if (serverAddressPort == null) {
            serverAddressPort = 27017;
        }

        Integer acceptableLatencyDifference = 
                datastoreConfig.getProperty("acceptableLatencyDifference", Integer.class);
        if (acceptableLatencyDifference != null) {
            //clientOptions.acceptableLatencyDifference(acceptableLatencyDifference);
            LOG.warn("acceptableLatencyDifference no longer used");
        }

        Integer connectTimeout = 
                datastoreConfig.getProperty("connectTimeout", Integer.class);
        if (connectTimeout != null) {
            clientOptions.connectTimeout(connectTimeout);
        }

        Integer connectionsPerHost = 
                datastoreConfig.getProperty("connectionsPerHost", Integer.class);
        if (connectionsPerHost != null) {
            clientOptions.connectionsPerHost(connectionsPerHost);
        }

        Boolean cursorFinalizerEnabled = 
                datastoreConfig.getProperty("acceptableLatencyDifference", Boolean.class);
        if (cursorFinalizerEnabled != null) {
            clientOptions.cursorFinalizerEnabled(cursorFinalizerEnabled);
        }

        Integer heartbeatConnectRetryFrequency = 
                datastoreConfig.getProperty("heartbeatConnectRetryFrequency", Integer.class);
        if (heartbeatConnectRetryFrequency != null) {
            //clientOptions.hheartbeatConnectRetryFrequency(heartbeatConnectRetryFrequency);
            LOG.warn("heartbeatConnectRetryFrequency no longer used");
        }

        Integer heartbeatConnectTimeout = 
                datastoreConfig.getProperty("heartbeatConnectTimeout", Integer.class);
        if (heartbeatConnectTimeout != null) {
            clientOptions.heartbeatConnectTimeout(heartbeatConnectTimeout);
        }

        Integer heartbeatFrequency = 
                datastoreConfig.getProperty("heartbeatFrequency", Integer.class);
        if (heartbeatFrequency != null) {
            clientOptions.heartbeatFrequency(heartbeatFrequency);
        }

        Integer heartbeatSocketTimeout = 
                datastoreConfig.getProperty("heartbeatSocketTimeout", Integer.class);
        if (heartbeatSocketTimeout != null) {
            clientOptions.heartbeatSocketTimeout(heartbeatSocketTimeout);
        }

        Integer heartbeatThreadCount = 
                datastoreConfig.getProperty("heartbeatThreadCount", Integer.class);
        if (heartbeatThreadCount != null) {
            // clientOptions.heartbeatThreadCount(heartbeatThreadCount);
            LOG.warn("heartbeatThreadCount no longer used");
        }

        Integer maxConnectionIdleTime = 
                datastoreConfig.getProperty("maxConnectionIdleTime", Integer.class);
        if (maxConnectionIdleTime != null) {
            clientOptions.maxConnectionIdleTime(maxConnectionIdleTime);
        }

        Integer maxConnectionLifeTime = 
                datastoreConfig.getProperty("maxConnectionLifeTime", Integer.class);
        if (maxConnectionLifeTime != null) {
            clientOptions.maxConnectionLifeTime(maxConnectionLifeTime);
        }

        Integer maxWaitTime = 
                datastoreConfig.getProperty("maxWaitTime", Integer.class);
        if (maxWaitTime != null) {
            clientOptions.maxWaitTime(maxWaitTime);
        }

        Integer minConnectionsPerHost = 
                datastoreConfig.getProperty("minConnectionsPerHost", Integer.class);
        if (minConnectionsPerHost != null) {
            clientOptions.minConnectionsPerHost(minConnectionsPerHost);
        }

        Boolean socketKeepAlive = 
                datastoreConfig.getProperty("socketKeepAlive", Boolean.class);
        if (socketKeepAlive != null) {
            clientOptions.socketKeepAlive(socketKeepAlive);
        }

        Integer socketTimeout = 
                datastoreConfig.getProperty("socketTimeout", Integer.class);
        if (socketTimeout != null) {
            clientOptions.socketTimeout(socketTimeout);
        }

        Integer threadsAllowedToBlockForConnectionMultiplier = 
                datastoreConfig.getProperty("threadsAllowedToBlockForConnectionMultiplier", Integer.class);
        if (threadsAllowedToBlockForConnectionMultiplier != null) {
            clientOptions.threadsAllowedToBlockForConnectionMultiplier(
                    threadsAllowedToBlockForConnectionMultiplier);
        }

        configureSsl(datastoreConfig, clientOptions);

        ServerAddress serverAddress = new ServerAddress(serverAddressHost, serverAddressPort);
        MongoClientOptions mongoClientOptions = clientOptions.build();
        return new MongoClient(serverAddress, mongoClientOptions);
    }

    private void configureSsl(DatastoreConfig datastoreConfig, MongoClientOptions.Builder clientOptions) {
        String certConfigLocation = datastoreConfig.getProperty("certConfigLocation", String.class);
        if (certConfigLocation != null) {
            LOG.info("looking for Mongo cert config information from {}", certConfigLocation);
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                JsonNode cfg = objectMapper.readTree(new URL(certConfigLocation));
                ServiceCertificate serviceCertificate = new ServiceCertificate(
                        cfg.get("Certificate").asText(),
                        cfg.get("CertificateChain").asText(),
                        cfg.get("PrivateKey").asText(),
                        cfg.get("Passphrase").asText()
                );

                SSLContext sslContext = serviceCertificate.getSSLContext();
                clientOptions
                        .sslEnabled(true)
                        .sslContext(sslContext);

            } catch (Exception e) {
                LOG.error("Unable to read mongo cert config from {}, {}", certConfigLocation, e.getMessage());
            }
        }
    }


    @Provides
    public Datastore providesMorphiaDatastore(MongoClient mongo, DatastoreConfig datastoreConfig) {
        String dbName = datastoreConfig.getProperty("dbName", String.class);
        if (dbName == null || dbName.isEmpty()) {
            dbName = "streamflow";
        }
        
        return new Morphia().createDatastore(mongo, dbName);
    }
}

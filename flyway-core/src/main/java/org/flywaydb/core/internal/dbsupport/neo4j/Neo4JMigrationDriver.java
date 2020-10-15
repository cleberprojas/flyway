/*
 * Copyright 2010-2017 Boxfuse GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.flywaydb.core.internal.dbsupport.neo4j;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import org.neo4j.driver.AuthToken;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Config;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.jdbc.Neo4jDriver;
import org.neo4j.jdbc.bolt.BoltDriver;
import org.neo4j.jdbc.bolt.cache.BoltDriverCache;
import org.neo4j.jdbc.bolt.impl.BoltNeo4jConnectionImpl;
import org.neo4j.jdbc.bolt.impl.BoltNeo4jDriverImpl;

public class Neo4JMigrationDriver extends BoltNeo4jDriverImpl {

    
    public static final String JDBC_BOLT_PREFIX = "bolt";
    
    private Driver driver;
    
    public Neo4JMigrationDriver() throws SQLException {
        super(JDBC_BOLT_PREFIX);
    }
    
    public Neo4JMigrationDriver(Properties props, String url) throws SQLException {
        super(JDBC_BOLT_PREFIX);
    }
    
    private static final BoltDriverCache cache = new BoltDriverCache(params ->
    {
        return GraphDatabase.driver(params.getRoutingUris().get(0), params.getAuthToken(), params.getConfig());
    }
    );

    static {
        try {
            BoltDriver driver = new BoltDriver();
            DriverManager.registerDriver(driver);
        } catch (SQLException e) {
            throw new ExceptionInInitializerError(e);
        }
    }
    
    
    @Override
    public Connection connect(String url, Properties props) throws SQLException {
        if (url == null) {
            throw new SQLException("null is not a valid url");
        }
        Connection connection = null;
        if (acceptsURL(url)) {
            String boltUrl = url.replace(Neo4jDriver.JDBC_PREFIX, "").replaceAll("^(" + getPrefix() + ":)([^/])", "$1//$2");
            try {
                Properties info = mergeUrlAndInfo(boltUrl, props);

                boltUrl = removeUrlProperties(boltUrl);
                Config.ConfigBuilder builder = createConfigBuilder(info);

                buildDriver(boltUrl, info, builder);
                connection = new BoltNeo4jConnectionImpl(driver, info, url);
                
            } catch (Exception e) {
                throw new SQLException(e);
            }
        }
        return connection;
    }

    private void buildDriver(String boltUrl, Properties info, Config.ConfigBuilder builder) throws URISyntaxException {
        Config config = builder.build();
        AuthToken authToken = getAuthToken(info);
        Properties routingContext = getRoutingContext(boltUrl, info);
        boltUrl = addRoutingPolicy(boltUrl, routingContext);
        List<URI> routingUris = buildRoutingUris(boltUrl, routingContext);
        driver = getDriver(routingUris, config, authToken, info);
        driver.verifyConnectivity();
    }

    private Config.ConfigBuilder createConfigBuilder(Properties info) throws SQLException {
        Config.ConfigBuilder builder = Config.builder();
        if (info.containsKey("nossl")) {
            builder = builder.withoutEncryption();
        }

        builder = setTrustStrategy(info, builder);
        builder = setConnectionAcquisitionTimeout(info, builder);
        builder = setIdleTimeBeforeConnectionTest(info, builder);
        builder = setConnectionTimeout(info, builder);
        builder = setEncryption(info, builder);
        builder = setLakedSessionLogging(info, builder);
        builder = setMaxConnectionLifetime(info, builder);
        builder = setMaxConnectionPoolSize(info, builder);
        builder = setMaxTransactionRetryTime(info, builder);
        return builder;
    }
    
    private AuthToken getAuthToken(Properties properties) {
        if (!properties.containsKey("user") ) {
            if(properties.containsKey("password")){
                //if only password is provided, try to authenticate with the default user: 'neo4j'
                return AuthTokens.basic("neo4j", properties.getProperty("password"));
            }
            //neither user nor password
            return AuthTokens.none();
        }
        //user provided, it need a password
        return AuthTokens.basic(properties.getProperty("user"), properties.getProperty("password"));
    }

    private String removeUrlProperties(String url) {
        String boltUrl = url;
        if (boltUrl.indexOf('?') != -1) {
            boltUrl = url.substring(0, url.indexOf('?'));
        }
        return boltUrl;
    }

   
    @Override
    protected Driver getDriver(List<URI> routingUris, Config config, AuthToken authToken, Properties info) throws URISyntaxException {
        return cache.getDriver(routingUris, config, authToken, info);
    }
    
    public Driver getDriver(){
        return this.driver;
    }
    
    

    @Override
    protected Properties getRoutingContext(String url, Properties properties) {
        return new Properties();
    }

    @Override
    protected String addRoutingPolicy(String url, Properties properties) {
        return url;
    }

    @Override
    protected List<URI> buildRoutingUris(String boltUrl, Properties properties) throws URISyntaxException {
        return Arrays.asList(new URI(boltUrl));
    }
    
    private Config.ConfigBuilder setTrustStrategy(Properties properties, Config.ConfigBuilder builder) throws SQLException {
        Config.ConfigBuilder newBuilder = builder;
        if (properties.containsKey(TRUST_STRATEGY_KEY)) {
            Config.TrustStrategy.Strategy strategy;
            try {
                strategy = Config.TrustStrategy.Strategy.valueOf((String) properties.get(TRUST_STRATEGY_KEY));
            } catch (IllegalArgumentException e) {
                throw new SQLException("Invalid value for trust.strategy param.", e);
            }
            switch (strategy) {
                case TRUST_SYSTEM_CA_SIGNED_CERTIFICATES:
                    newBuilder = builder.withTrustStrategy(Config.TrustStrategy.trustSystemCertificates());
                    break;
                case TRUST_CUSTOM_CA_SIGNED_CERTIFICATES:
                    newBuilder = handleTrustStrategyWithFile(properties, strategy, builder);
                    break;
                case TRUST_ALL_CERTIFICATES:
                default:
                    newBuilder = builder.withTrustStrategy(Config.TrustStrategy.trustAllCertificates());
                    break;
            }
        }
        return newBuilder;
    }
    
    private Config.ConfigBuilder handleTrustStrategyWithFile(Properties properties, Config.TrustStrategy.Strategy strategy, Config.ConfigBuilder builder)
            throws SQLException {
        if (properties.containsKey(TRUSTED_CERTIFICATE_KEY)) {
            Config.ConfigBuilder newBuilder;
            switch (strategy) {
                case TRUST_CUSTOM_CA_SIGNED_CERTIFICATES:
                    String value = properties.getProperty(TRUSTED_CERTIFICATE_KEY);
                    newBuilder = builder.withTrustStrategy(Config.TrustStrategy.trustCustomCertificateSignedBy(new File(value)));
                    break;
                default:
                    newBuilder = builder;
                    break;
            }
            return newBuilder;
        } else {
            throw new SQLException("Missing parameter 'trusted.certificate.file' : A FILE IS REQUIRED");
        }
    }


    /**
     * Get a value from the properties and try to apply it to the builder
     * @param info
     * @param builder
     * @param key
     * @param op
     * @param errorMessage
     * @return
     */
    private Config.ConfigBuilder setValueConfig(Properties info, Config.ConfigBuilder builder, String key, Function<String,Config.ConfigBuilder> op, String errorMessage) {
        if(info.containsKey(key)){
            String value = info.getProperty(key);
            try{
                return op.apply(value);
            }catch(Exception e){
                throw new IllegalArgumentException(key+": "+value+" "+errorMessage);
            }

        }
        return builder;
    }

    /**
     * Get a long value from the properties and apply it to the builder
     * @param info
     * @param builder
     * @param key
     * @param op
     * @return
     */
    private Config.ConfigBuilder setLongConfig(Properties info, Config.ConfigBuilder builder, String key, Function<Long,Config.ConfigBuilder> op) {
        return setValueConfig(info, builder, key, (val)->op.apply(Long.parseLong(val)), "is not a number");
    }

    /**
     * Get a boolean value from the properties and apply it to the builder
     * @param info
     * @param builder
     * @param key
     * @param op
     * @return
     */
    private Config.ConfigBuilder setBooleanConfig(Properties info, Config.ConfigBuilder builder, String key, Function<Boolean,Config.ConfigBuilder> op) {
        return setValueConfig(info, builder, key, (val)->{
            if ("true".equalsIgnoreCase(val) || "false".equalsIgnoreCase(val)) {
                return op.apply(Boolean.parseBoolean(val));
            }else{
                throw new IllegalArgumentException();
            }
        }, "is not a boolean");
    }

    /**
     * Configure CONNECTION_ACQUISITION_TIMEOUT
     * @param info
     * @param builder
     * @return always a builder
     */
    private Config.ConfigBuilder setConnectionAcquisitionTimeout(Properties info, Config.ConfigBuilder builder) {
        return setLongConfig(info, builder, CONNECTION_ACQUISITION_TIMEOUT, (ms)->builder.withConnectionAcquisitionTimeout(ms, TimeUnit.MILLISECONDS));
    }

    /**
     * Configure CONNECTION_LIVENESS_CHECK_TIMEOUT
     * @param info
     * @param builder
     * @return always a builder
     */
    private Config.ConfigBuilder setIdleTimeBeforeConnectionTest(Properties info, Config.ConfigBuilder builder) {
        return setLongConfig(info, builder, CONNECTION_LIVENESS_CHECK_TIMEOUT, (ms)->builder.withConnectionLivenessCheckTimeout(ms, TimeUnit.MINUTES));
    }

    /**
     * Configure CONNECTION_TIMEOUT
     * @param info
     * @param builder
     * @return always a builder
     */
    private Config.ConfigBuilder setConnectionTimeout(Properties info, Config.ConfigBuilder builder) {
        return setLongConfig(info, builder, CONNECTION_TIMEOUT, (ms)->builder.withConnectionTimeout(ms, TimeUnit.MILLISECONDS));
    }

    /**
     * Configure ENCRYPTION
     * @param info
     * @param builder
     * @return always a builder
     */
    private Config.ConfigBuilder setEncryption(Properties info, Config.ConfigBuilder builder) {
        return setBooleanConfig(info, builder, ENCRYPTION, (condition)-> (condition)?builder.withEncryption():builder.withoutEncryption());
    }

    /**
     * Configure LEAKED_SESSIONS_LOGGING
     * @param info
     * @param builder
     * @return always a builder
     */
    private Config.ConfigBuilder setLakedSessionLogging(Properties info, Config.ConfigBuilder builder) {
        return setBooleanConfig(info, builder, LEAKED_SESSIONS_LOGGING, (condition)-> (condition)?builder.withLeakedSessionsLogging():builder);
    }

    /**
     * Configure MAX_CONNECTION_LIFETIME
     * @param info
     * @param builder
     * @return always a builder
     */
    private Config.ConfigBuilder setMaxConnectionLifetime(Properties info, Config.ConfigBuilder builder) {
        return setLongConfig(info, builder, MAX_CONNECTION_LIFETIME, (ms)->builder.withMaxConnectionLifetime(ms, TimeUnit.MILLISECONDS));
    }

    /**
     * Configure MAX_CONNECTION_POOLSIZE
     * @param info
     * @param builder
     * @return always a builder
     */
    private Config.ConfigBuilder setMaxConnectionPoolSize(Properties info, Config.ConfigBuilder builder) {
        return setValueConfig(info, builder, MAX_CONNECTION_POOLSIZE, (val)->builder.withMaxConnectionPoolSize(Integer.parseInt(val)),"is not a number");
    }

    /**
     * Configure MAX_TRANSACTION_RETRY_TIME
     * @param info
     * @param builder
     * @return always a builder
     */
    private Config.ConfigBuilder setMaxTransactionRetryTime(Properties info, Config.ConfigBuilder builder) {
        return setLongConfig(info, builder, MAX_TRANSACTION_RETRY_TIME, (ms)->builder.withMaxTransactionRetryTime(ms, TimeUnit.MILLISECONDS));
    }

}

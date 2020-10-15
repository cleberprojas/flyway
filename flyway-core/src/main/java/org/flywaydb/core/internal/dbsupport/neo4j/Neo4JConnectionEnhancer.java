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

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

//import org.neo4j.driver.v1.Session;

import org.neo4j.driver.Driver;
import org.neo4j.jdbc.bolt.BoltNeo4jConnection;
import net.sf.cglib.proxy.Enhancer;
import net.sf.cglib.proxy.MethodInterceptor;
import net.sf.cglib.proxy.MethodProxy;

/**
 * @author Felipe Nascimento (ScuteraTech)
 *
 */
public class Neo4JConnectionEnhancer  {

	static Connection enhancedConnection(Driver driver, Connection connection, String url, Properties info) throws SQLException {
        Enhancer enhancer = new Enhancer();
        enhancer.setCallback(new MethodInterceptor() {
            @Override
            public Object intercept(Object target, Method method, Object[] arguments, MethodProxy methodProxy) throws Throwable {
                if (method.getName().equals("createStatement")) {
                    Statement statement = (Statement) method.invoke(connection, arguments);

                    Statement proxyStatement = (Statement) Proxy.newProxyInstance(
                            Neo4JStatementProxy.class.getClassLoader(), new Class[] { Statement.class },
                            new Neo4JStatementProxy(statement));

                    return proxyStatement;
                }
                return method.invoke(connection, arguments);
            }
        });

        enhancer.setSuperclass(connection.getClass());
        Class<?>[] argumentTypes = { Driver.class, Properties.class, String.class };
        Object[] arguments = { driver, info, url };
        Connection proxyConnection = (Connection) enhancer.create(argumentTypes, arguments);
        return proxyConnection;
	}

}

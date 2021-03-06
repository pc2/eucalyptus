/*******************************************************************************
 *Copyright (c) 2009 Eucalyptus Systems, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, only version 3 of the License.
 * 
 * 
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Please contact Eucalyptus Systems, Inc., 130 Castilian
 * Dr., Goleta, CA 93101 USA or visit <http://www.eucalyptus.com/licenses/>
 * if you need additional information or have any questions.
 * 
 * This file may incorporate work covered under the following copyright and
 * permission notice:
 * 
 * Software License Agreement (BSD License)
 * 
 * Copyright (c) 2008, Regents of the University of California
 * All rights reserved.
 * 
 * Redistribution and use of this software in source and binary forms, with
 * or without modification, are permitted provided that the following
 * conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. USERS OF
 * THIS SOFTWARE ACKNOWLEDGE THE POSSIBLE PRESENCE OF OTHER OPEN SOURCE
 * LICENSED MATERIAL, COPYRIGHTED MATERIAL OR PATENTED MATERIAL IN THIS
 * SOFTWARE, AND IF ANY SUCH MATERIAL IS DISCOVERED THE PARTY DISCOVERING
 * IT MAY INFORM DR. RICH WOLSKI AT THE UNIVERSITY OF CALIFORNIA, SANTA
 * BARBARA WHO WILL THEN ASCERTAIN THE MOST APPROPRIATE REMEDY, WHICH IN
 * THE REGENTS’ DISCRETION MAY INCLUDE, WITHOUT LIMITATION, REPLACEMENT
 * OF THE CODE SO IDENTIFIED, LICENSING OF THE CODE SO IDENTIFIED, OR
 * WITHDRAWAL OF THE CODE CAPABILITY TO THE EXTENT NEEDED TO COMPLY WITH
 * ANY SUCH LICENSES OR RIGHTS.
 *******************************************************************************/
/*
 * Author: chris grzegorczyk <grze@eucalyptus.com>
 */
package com.eucalyptus.config;

import java.util.List;

import org.apache.log4j.Logger;

import com.eucalyptus.bootstrap.Component;
import com.eucalyptus.event.EventVetoedException;
import com.eucalyptus.event.ListenerRegistry;
import com.eucalyptus.event.StartComponentEvent;
import com.eucalyptus.event.StopComponentEvent;
import com.eucalyptus.util.EntityWrapper;
import com.eucalyptus.util.EucalyptusCloudException;
import com.eucalyptus.util.NetworkUtil;

import edu.ucsb.eucalyptus.msgs.ComponentInfoType;
import edu.ucsb.eucalyptus.msgs.DeregisterClusterType;
import edu.ucsb.eucalyptus.msgs.DeregisterComponentResponseType;
import edu.ucsb.eucalyptus.msgs.DeregisterComponentType;
import edu.ucsb.eucalyptus.msgs.DescribeComponentsResponseType;
import edu.ucsb.eucalyptus.msgs.DescribeComponentsType;
import edu.ucsb.eucalyptus.msgs.RegisterClusterType;
import edu.ucsb.eucalyptus.msgs.RegisterComponentResponseType;
import edu.ucsb.eucalyptus.msgs.RegisterComponentType;
import edu.ucsb.eucalyptus.msgs.RegisterStorageControllerType;
import edu.ucsb.eucalyptus.msgs.RegisterWalrusType;

public class Configuration {
  static Logger         LOG                 = Logger.getLogger( Configuration.class );
  private static String DB_NAME             = "eucalyptus_config";
  static String         CLUSTER_KEY_FSTRING = "cc-%s";
  static String         NODE_KEY_FSTRING    = "nc-%s";

  public static <T> EntityWrapper<T> getEntityWrapper( ) {
    return new EntityWrapper<T>( Configuration.DB_NAME );
  }

  public RegisterComponentResponseType registerComponent( RegisterComponentType request ) throws EucalyptusCloudException {
    RegisterComponentResponseType reply = ( RegisterComponentResponseType ) request.getReply( );
    reply.set_return( true );
    boolean isGood;
    try {
      if( !NetworkUtil.testGoodAddress( request.getHost( ) ) ) {
        throw new EucalyptusCloudException( "Components cannot be registered using local, link-local, or multicast addresses." );        
      }
      if( request instanceof RegisterClusterType && !ConfigurationUtil.testClusterCredentialsDirectory( request.getName( ) ) ) {
        throw new EucalyptusCloudException( "Cluster registration failed because the key directory cannot be created." );
      }
    } catch ( EucalyptusCloudException e ) {
      throw e;
    } catch ( Exception e1 ) {
      throw new EucalyptusCloudException( e1.getMessage( ), e1 );
    }
    try {
      if ( ConfigurationUtil.checkComponentExists( request ) ) {
        return reply;
      }
    } catch ( Exception e2 ) {
      throw new EucalyptusCloudException( e2 );
    }
    if ( request instanceof RegisterStorageControllerType && NetworkUtil.testLocal( request.getHost( ) ) && !Component.storage.isLocal( ) ) {
      throw new EucalyptusCloudException( "You do not have a local storage controller enabled (or it is not installed)." );
    } else if ( request instanceof RegisterWalrusType && NetworkUtil.testLocal( request.getHost( ) ) && !Component.walrus.isLocal( ) ) { 
      throw new EucalyptusCloudException( "You do not have a local walrus enabled (or it is not installed)." );
    } else if ( request instanceof RegisterStorageControllerType ) {
      try {
        Configuration.getClusterConfiguration( request.getName( ) );
      } catch ( Exception e1 ) {
        throw new EucalyptusCloudException( "Storage controllers may only be registered with a corresponding Cluster of the same name.  No cluster found with the name: " + request.getName( ) );
      }
    }
    EntityWrapper<ComponentConfiguration> db = Configuration.getEntityWrapper( );
    ComponentConfiguration newComponent;
    try {
      newComponent = ConfigurationUtil.getConfigurationInstance( request, request.getName( ), NetworkUtil.tryToResolve( request.getHost( ) ), request.getPort( ) );
      db.add( newComponent );
      db.commit( );
    } catch ( Exception e ) {
      db.rollback( );
      LOG.error( e, e );
      throw new EucalyptusCloudException( e );
    }
    if ( request instanceof RegisterClusterType ) {
      ConfigurationUtil.setupClusterCredentials( newComponent );
    }
    fireStartComponent( newComponent );
    return reply;
  }

  public static void fireStartComponent( ComponentConfiguration newComponent ) throws EucalyptusCloudException {
    StartComponentEvent e = null;
    if ( Component.walrus.equals( newComponent.getComponent( ) ) && NetworkUtil.testLocal( newComponent.getHostName( ) ) ) {
      e = StartComponentEvent.getLocal( newComponent );
    } else if ( Component.storage.equals( newComponent.getComponent( ) ) && ( NetworkUtil.testLocal( newComponent.getHostName( ) ) ) ) {
      e = StartComponentEvent.getLocal( newComponent );
    } else {
      e = StartComponentEvent.getRemote( newComponent );
    }
    try {
      ListenerRegistry.getInstance( ).fireEvent( newComponent.getComponent( ), e );
    } catch ( EventVetoedException e1 ) {
      throw new EucalyptusCloudException( e1.getMessage( ), e1 );
    }
  }

  public DeregisterComponentResponseType deregisterComponent( DeregisterComponentType request ) throws EucalyptusCloudException {
    DeregisterComponentResponseType reply = ( DeregisterComponentResponseType ) request.getReply( );
    reply.set_return( true );
    EntityWrapper<ComponentConfiguration> db = null;
    ComponentConfiguration componentConfig = null;
    try {
      db = Configuration.getEntityWrapper( );
      ComponentConfiguration searchConfig = ConfigurationUtil.getConfigurationInstance( request );
      searchConfig.setName( request.getName( ) );
      componentConfig = db.getUnique( searchConfig );
      db.delete( componentConfig );
      db.commit( );
    } catch ( Exception e ) {
      db.rollback( );
      return reply;
//      throw new EucalyptusCloudException( "Failed to find configuration for " + request.getClass( ).getSimpleName( ) + " named " + request.getName( ) );
    }
    if ( request instanceof DeregisterClusterType ) {
      try {
        ConfigurationUtil.removeClusterCredentials( request.getName( ) );
      } catch ( Exception e ) {
        LOG.error( "BUG: removed cluster but failed to remove the credentials." );
      }
      try {
        db = Configuration.getEntityWrapper( );
        StorageControllerConfiguration searchConfig = new StorageControllerConfiguration( );
        searchConfig.setName( request.getName( ) );
        ComponentConfiguration scComponentConfig = db.getUnique( searchConfig );
        db.delete( scComponentConfig );
        db.commit( );
      } catch ( Exception e ) {
        db.rollback( );
      }
    }
    fireStopComponent( componentConfig );
    return reply;
  }

  public static void fireStopComponent( ComponentConfiguration componentConfig ) throws EucalyptusCloudException {
    StopComponentEvent e = null;
    if ( Component.walrus.equals( componentConfig.getComponent( ) ) && NetworkUtil.testLocal( componentConfig.getHostName( ) ) ) {
      e = StopComponentEvent.getLocal( componentConfig );
    } else if ( Component.storage.equals( componentConfig.getComponent( ) ) && NetworkUtil.testLocal( componentConfig.getHostName( ) ) ) {
      e = StopComponentEvent.getLocal( componentConfig );
    } else {
      e = StopComponentEvent.getRemote( componentConfig );
    }
    try {
      ListenerRegistry.getInstance( ).fireEvent( componentConfig.getComponent( ), e );
    } catch ( EventVetoedException e1 ) {
      throw new EucalyptusCloudException( e1.getMessage( ), e1 );
    }
  }

  public DescribeComponentsResponseType listComponents( DescribeComponentsType request ) throws EucalyptusCloudException {
    DescribeComponentsResponseType reply = ( DescribeComponentsResponseType ) request.getReply( );
    ComponentConfiguration searchConfig;
    try {
      searchConfig = ConfigurationUtil.getConfigurationInstance( request );
    } catch ( Exception e1 ) {
      LOG.error( "Failed to find configuration type for request of type: " + request.getClass( ).getSimpleName( ) );
      throw new EucalyptusCloudException( "Failed to find configuration type for request of type: " + request.getClass( ).getSimpleName( ) );
    }
    List<ComponentInfoType> listConfigs = reply.getRegistered( );
    EntityWrapper<ComponentConfiguration> db = Configuration.getEntityWrapper( );
    try {
      List<ComponentConfiguration> componentList = db.query( searchConfig );
      for ( ComponentConfiguration c : componentList ) {
        listConfigs.add( new ComponentInfoType( c.getName( ), c.getHostName( ) ) );
      }
      db.commit( );
    } catch ( Exception e ) {
      LOG.error( e, e );
      db.commit( );
      throw new EucalyptusCloudException( e );
    } catch ( Throwable t ) {
      db.commit( );
    }
    return reply;
  }

  public static List<ClusterConfiguration> getClusterConfigurations( ) throws EucalyptusCloudException {
    EntityWrapper<ClusterConfiguration> db = Configuration.getEntityWrapper( );
    try {
      List<ClusterConfiguration> componentList = db.query( new ClusterConfiguration( ) );
      for( ClusterConfiguration cc : componentList ) {
        if( cc.getMinVlan( ) == null ) cc.setMinVlan( 10 );
        if( cc.getMaxVlan( ) == null ) cc.setMaxVlan( 4095 );
      }
      db.commit( );
      return componentList;
    } catch ( Exception e ) {
      db.rollback( );
      LOG.error( e, e );
      throw new EucalyptusCloudException( e );
    }
  }

  public static List<StorageControllerConfiguration> getStorageControllerConfigurations( ) throws EucalyptusCloudException {
    EntityWrapper<StorageControllerConfiguration> db = Configuration.getEntityWrapper( );
    try {
      List<StorageControllerConfiguration> componentList = db.query( new StorageControllerConfiguration( ) );
      db.commit( );
      return componentList;
    } catch ( Exception e ) {
      db.rollback( );
      LOG.error( e, e );
      throw new EucalyptusCloudException( e );
    }
  }

  public static List<WalrusConfiguration> getWalrusConfigurations( ) throws EucalyptusCloudException {
    EntityWrapper<WalrusConfiguration> db = Configuration.getEntityWrapper( );
    try {
      List<WalrusConfiguration> componentList = db.query( new WalrusConfiguration( ) );
      db.commit( );
      return componentList;
    } catch ( Exception e ) {
      db.rollback( );
      LOG.error( e, e );
      throw new EucalyptusCloudException( e );
    }
  }

  public static StorageControllerConfiguration getStorageControllerConfiguration( String scName ) throws EucalyptusCloudException {
    List<StorageControllerConfiguration> scs = Configuration.getStorageControllerConfigurations( );
    for ( StorageControllerConfiguration sc : scs ) {
      if ( sc.getName( ).equals( scName ) ) {
        return sc;
      }
    }
    throw new NoSuchComponentException( StorageControllerConfiguration.class.getSimpleName( ) + " named " + scName );
  }

  public static WalrusConfiguration getWalrusConfiguration( String walrusName ) throws EucalyptusCloudException {
    List<WalrusConfiguration> walri = Configuration.getWalrusConfigurations( );
    for ( WalrusConfiguration w : walri ) {
      if ( w.getName( ).equals( walrusName ) ) {
        return w;
      }
    }
    throw new NoSuchComponentException( WalrusConfiguration.class.getSimpleName( ) + " named " + walrusName );
  }

  public static ClusterConfiguration getClusterConfiguration( String clusterName ) throws EucalyptusCloudException {
    List<ClusterConfiguration> clusters = Configuration.getClusterConfigurations( );
    for ( ClusterConfiguration c : clusters ) {
      if ( c.getName( ).equals( clusterName ) ) {
        return c;
      }
    }
    throw new NoSuchComponentException( ClusterConfiguration.class.getSimpleName( ) + " named " + clusterName );
  }
}

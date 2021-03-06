/*******************************************************************************
*Copyright (c) 2009  Eucalyptus Systems, Inc.
* 
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, only version 3 of the License.
* 
* 
*  This file is distributed in the hope that it will be useful, but WITHOUT
*  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
*  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
*  for more details.
* 
*  You should have received a copy of the GNU General Public License along
*  with this program.  If not, see <http://www.gnu.org/licenses/>.
* 
*  Please contact Eucalyptus Systems, Inc., 130 Castilian
*  Dr., Goleta, CA 93101 USA or visit <http://www.eucalyptus.com/licenses/>
*  if you need additional information or have any questions.
* 
*  This file may incorporate work covered under the following copyright and
*  permission notice:
* 
*    Software License Agreement (BSD License)
* 
*    Copyright (c) 2008, Regents of the University of California
*    All rights reserved.
* 
*    Redistribution and use of this software in source and binary forms, with
*    or without modification, are permitted provided that the following
*    conditions are met:
* 
*      Redistributions of source code must retain the above copyright notice,
*      this list of conditions and the following disclaimer.
* 
*      Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in the
*      documentation and/or other materials provided with the distribution.
* 
*    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
*    IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
*    TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
*    PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
*    OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
*    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
*    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
*    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
*    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
*    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
*    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. USERS OF
*    THIS SOFTWARE ACKNOWLEDGE THE POSSIBLE PRESENCE OF OTHER OPEN SOURCE
*    LICENSED MATERIAL, COPYRIGHTED MATERIAL OR PATENTED MATERIAL IN THIS
*    SOFTWARE, AND IF ANY SUCH MATERIAL IS DISCOVERED THE PARTY DISCOVERING
*    IT MAY INFORM DR. RICH WOLSKI AT THE UNIVERSITY OF CALIFORNIA, SANTA
*    BARBARA WHO WILL THEN ASCERTAIN THE MOST APPROPRIATE REMEDY, WHICH IN
*    THE REGENTS’ DISCRETION MAY INCLUDE, WITHOUT LIMITATION, REPLACEMENT
*    OF THE CODE SO IDENTIFIED, LICENSING OF THE CODE SO IDENTIFIED, OR
*    WITHDRAWAL OF THE CODE CAPABILITY TO THE EXTENT NEEDED TO COMPLY WITH
*    ANY SUCH LICENSES OR RIGHTS.
*******************************************************************************/
/*
 * Author: chris grzegorczyk <grze@eucalyptus.com>
 */
package com.eucalyptus.bootstrap;

import java.util.List;

import org.apache.log4j.Logger;
import org.mule.RegistryContext;
import org.mule.api.MuleContext;
import org.mule.api.context.MuleContextFactory;
import org.mule.api.registry.Registry;
import org.mule.config.ConfigResource;
import org.mule.config.spring.SpringXmlConfigurationBuilder;
import org.mule.context.DefaultMuleContextFactory;

import com.eucalyptus.util.LogUtil;
import com.google.common.collect.Lists;

@Provides(resource=Resource.CloudService)
public class ServiceBootstrapper extends Bootstrapper {
  private static Logger LOG = Logger.getLogger( ServiceBootstrapper.class );
  private MuleContext context;
  private MuleContextFactory contextFactory;
  private SpringXmlConfigurationBuilder builder;
  private static Registry registry;
  private static ServiceBootstrapper singleton;
  
  public static Registry getRegistry() {
      return registry;
  }
  
  public static ServiceBootstrapper getInstance() {
    synchronized ( ServiceBootstrapper.class ) {
      if( singleton == null ) {
        singleton = new ServiceBootstrapper( );
      }
      return singleton;
    }
  }
  
  private ServiceBootstrapper( ) {
    super( );
    this.contextFactory = new DefaultMuleContextFactory( );
  }

  @Override
  public boolean load( Resource current ) throws Exception {
    List<ConfigResource> configs = Lists.newArrayList( );
    for( ResourceProvider r : current.getProviders( ) ) {
      LOG.info( LogUtil.subheader( "Preparing configuration for: " + r ) );
      configs.addAll( r.getConfigurations( ) );
    }
    for( ConfigResource cfg : configs ) {
      LOG.info( "-> Loaded cfg: " + cfg.getUrl( ) );
    }
    try {
      registry = RegistryContext.getOrCreateRegistry( );
      this.builder = new SpringXmlConfigurationBuilder( configs.toArray( new ConfigResource[]{} ) );
    } catch ( Exception e ) {
      LOG.fatal( "Failed to bootstrap services.", e );
      return false;
    }
    return true;
  }

  @Override
  public boolean start( ) throws Exception {
    try {
      LOG.info( "Starting up system bus.");
      this.context = this.contextFactory.createMuleContext( this.builder );
    } catch ( Exception e ) {
      LOG.fatal( "Failed to configure services.", e );
      return false;
    }
    try {
      this.context.start( );
    } catch ( Exception e ) {
      LOG.fatal( "Failed to start services.", e );
      return false;
    }
    return true;
  }

  @Override
  public boolean stop( ) throws Exception {
    this.context.stop( );
    return true;
  }

  
}

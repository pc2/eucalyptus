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
package edu.ucsb.eucalyptus;

import edu.ucsb.eucalyptus.cloud.entities.CertificateInfo;
import edu.ucsb.eucalyptus.cloud.entities.Counters;
import edu.ucsb.eucalyptus.cloud.entities.ImageInfo;
import edu.ucsb.eucalyptus.cloud.entities.UserGroupInfo;
import edu.ucsb.eucalyptus.cloud.entities.UserInfo;
import edu.ucsb.eucalyptus.cloud.entities.ObjectInfo;
import edu.ucsb.eucalyptus.cloud.entities.VmType;
import edu.ucsb.eucalyptus.cloud.entities.SystemConfiguration;
import edu.ucsb.eucalyptus.msgs.Volume;
import edu.ucsb.eucalyptus.util.SystemUtil;
import edu.ucsb.eucalyptus.util.UserManagement;
import com.eucalyptus.util.StorageProperties;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.UrlBase64;
import org.hibernate.HibernateException;
import org.mortbay.jetty.security.Credential;

import com.eucalyptus.auth.Credentials;
import com.eucalyptus.auth.util.AbstractKeyStore;
import com.eucalyptus.auth.util.EucaKeyStore;
import com.eucalyptus.bootstrap.Component;
import com.eucalyptus.util.BaseDirectory;
import com.eucalyptus.util.DatabaseUtil;
import com.eucalyptus.util.EntityWrapper;
import com.eucalyptus.util.EucalyptusCloudException;
import com.eucalyptus.util.EucalyptusProperties;
import com.eucalyptus.util.SubDirectory;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;

public class StartupChecks {

  private static String _KS_FORMAT     = "bks";
  private static String _KS_PASS       = Component.eucalyptus.name( );
  private static String _USER_KS       = BaseDirectory.CONF.toString( ) + File.separator + "users." + _KS_FORMAT.toLowerCase( );
  private static Logger LOG            = Logger.getLogger( StartupChecks.class );
  private static String HEADER_FSTRING = "=================================:: %-20s ::=================================";


  private static void fail( String... error ) {
    for ( String s : error )
      LOG.fatal( s );
    if ( DatabaseUtil.getEntityManagerFactory( Component.eucalyptus.name( ) ).isOpen( ) ) {
      DatabaseUtil.getEntityManagerFactory( Component.eucalyptus.name( ) ).close( );
    }
    SystemUtil.shutdownWithError( String.format( HEADER_FSTRING, "STARTUP FAILURE" ) );
  }

  public static boolean doChecks( ) {
    StartupChecks.checkDirectories( );


    boolean hasDb = StartupChecks.checkDatabase( );

    if ( !hasDb ) {
      StartupChecks.createDb( );
      hasDb = StartupChecks.checkDatabase( );
    }

    if ( !hasDb ) {
      LOG.fatal( String.format( HEADER_FSTRING, "STARTUP FAILURE" ) );
      if ( !hasDb ) LOG.fatal( "Failed to initialize the database in: " + SubDirectory.DB );
      StartupChecks.fail( "See errors messages above." );
    }


    EntityWrapper<ImageInfo> db2 = new EntityWrapper<ImageInfo>( );
    try {
      List<ImageInfo> imageList = db2.query( new ImageInfo( ) );
      for ( ImageInfo image : imageList ) {
        if ( image.getImageLocation( ).split( "/" ).length != 2 ) {
          LOG.info( "Image with invalid location, needs to be reregistered: " + image.getImageId( ) );
          LOG.info( "Removing entry for: " + image.getImageId( ) );
          db2.delete( image );
        }
      }
      db2.commit( );
    } catch ( Exception e1 ) {
      db2.rollback( );
    }

    checkWalrus( );
    checkStorage( );

    return true;
  }

  private static void checkWalrus( ) {
    EntityWrapper<ObjectInfo> db = new EntityWrapper<ObjectInfo>( );
    ObjectInfo searchObjectInfo = new ObjectInfo( );
    List<ObjectInfo> objectInfos = db.query( searchObjectInfo );
    for ( ObjectInfo objectInfo : objectInfos ) {
      if ( objectInfo.getObjectKey( ) == null ) objectInfo.setObjectKey( objectInfo.getObjectName( ) );
    }
    db.commit( );
  }

  private static void checkStorage( ) {
    EntityWrapper<SystemConfiguration> db = new EntityWrapper<SystemConfiguration>( );
    try {
      SystemConfiguration systemConfig = db.getUnique( new SystemConfiguration( ) );
      //if ( systemConfig.getStorageVolumesDir( ) == null ) systemConfig.setStorageVolumesDir( StorageProperties.storageRootDirectory );
    } catch ( EucalyptusCloudException ex ) {
    }
    db.commit( );
  }

  public static boolean checkDatabase( ) {
    /** initialize the counters **/

    EntityWrapper<UserInfo> db = new EntityWrapper<UserInfo>( );
    EntityWrapper<Volume> db2 = new EntityWrapper<Volume>( "eucalyptus_volumes" );
    try {
      UserInfo adminUser = db.getUnique( new UserInfo( "admin" ) );
      db.rollback( );
      return true;
    } catch ( EucalyptusCloudException e ) {
      db.rollback( );
      return false;
    } 
  }
 
  public static boolean createDb( ) {
    EntityWrapper<VmType> db2 = new EntityWrapper<VmType>( );
    try {
      if( db2.query( new VmType() ).size( ) == 0 ) { 
        db2.add( new VmType( "m1.small", 1, 2, 128 ) );
        db2.add( new VmType( "c1.medium", 1, 5, 256 ) );
        db2.add( new VmType( "m1.large", 2, 10, 512 ) );
        db2.add( new VmType( "m1.xlarge", 2, 20, 1024 ) );
        db2.add( new VmType( "c1.xlarge", 4, 20, 2048 ) );
      }
      db2.commit( );
    } catch ( Exception e ) {
      db2.rollback( );
      return false;
    }
    EntityWrapper<UserGroupInfo> db3 = new EntityWrapper<UserGroupInfo>( );
    try {
      db3.getUnique( new UserGroupInfo( "all" ) );
      db3.commit( );
    } catch ( EucalyptusCloudException e ) {
      db3.add( new UserGroupInfo( "all" ) );
      db3.commit( );
    }
    try {
      UserGroupInfo allGroup = UserGroupInfo.named( "all" );
    } catch ( EucalyptusCloudException e1 ) {
    }
    EntityWrapper<UserInfo> db = new EntityWrapper<UserInfo>( );
    try {
      db.getUnique( new UserInfo("admin") );
      db.commit( );
      return true;
    } catch ( Exception e ) {
      try {
        db.getSession( ).persist( new Counters( ) );
        UserInfo u = UserManagement.generateAdmin( );
        db.add( u );
        db.commit( );
      } catch ( HibernateException e1 ) {
        db.rollback( );
        return false;
      }
      return true;
    }
  }

  private static void checkDirectories( ) {
    for ( BaseDirectory dir : BaseDirectory.values( ) )
      dir.check( );
    SubDirectory.KEYS.create( );
  }

}

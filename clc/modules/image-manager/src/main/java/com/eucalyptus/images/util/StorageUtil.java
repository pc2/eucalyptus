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
package com.eucalyptus.images.util;

import java.util.Map;

import org.apache.log4j.Logger;

import com.eucalyptus.bootstrap.Component;
import com.eucalyptus.config.Configuration;
import com.eucalyptus.config.StorageControllerConfiguration;
import com.eucalyptus.util.EucalyptusCloudException;
import com.eucalyptus.ws.client.ServiceDispatcher;
import com.google.common.collect.Lists;

import edu.ucsb.eucalyptus.cloud.state.Volume;
import edu.ucsb.eucalyptus.msgs.AttachedVolume;
import edu.ucsb.eucalyptus.msgs.DescribeStorageVolumesResponseType;
import edu.ucsb.eucalyptus.msgs.DescribeStorageVolumesType;
import edu.ucsb.eucalyptus.msgs.EucalyptusMessage;
import edu.ucsb.eucalyptus.msgs.StorageVolume;

public class StorageUtil {
  private static Logger LOG = Logger.getLogger( StorageUtil.class );
  
  public static ServiceDispatcher lookup( String hostName ) {
    return ServiceDispatcher.lookup( Component.storage, hostName );
  }
  
  public static void dispatchAll( EucalyptusMessage message ) throws EucalyptusCloudException {
    for( ServiceDispatcher sc : ServiceDispatcher.lookupMany( Component.storage ) ) {
      sc.dispatch( message );
    }
  }

  public static edu.ucsb.eucalyptus.msgs.Volume getVolumeReply( Map<String, AttachedVolume> attachedVolumes, Volume v ) throws EucalyptusCloudException {
    StorageControllerConfiguration scConfig = Configuration.getStorageControllerConfiguration( v.getCluster( ) );
    DescribeStorageVolumesType descVols = new DescribeStorageVolumesType( Lists.newArrayList( v.getDisplayName() ) );
    ServiceDispatcher sc = ServiceDispatcher.lookup( Component.storage, scConfig.getHostName( ) );
    DescribeStorageVolumesResponseType volState = sc.send( descVols, DescribeStorageVolumesResponseType.class );
    LOG.trace( volState );
    String volumeState = "unavailable";
    if ( !volState.getVolumeSet().isEmpty() ) {
      StorageVolume vol = volState.getVolumeSet().get( 0 );
      volumeState = vol.getStatus();
      v.setSize( new Integer( vol.getSize() ) );
      v.setRemoteDevice( vol.getActualDeviceName() );
    }
    if ( attachedVolumes.containsKey( v.getDisplayName() ) ) {
      volumeState = "in-use";
    }
    v.setMappedState( volumeState );
    edu.ucsb.eucalyptus.msgs.Volume aVolume = v.morph( new edu.ucsb.eucalyptus.msgs.Volume() );
    if ( attachedVolumes.containsKey( v.getDisplayName() ) ) {
      aVolume.setStatus( volumeState );
      aVolume.getAttachmentSet().add( attachedVolumes.get( aVolume.getVolumeId() ) );
    }
    return aVolume;
  }
}

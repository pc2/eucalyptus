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
package com.eucalyptus.util;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.List;

import org.apache.log4j.Logger;

import com.google.common.collect.Lists;

public class NetworkUtil {
  private static Logger LOG = Logger.getLogger( NetworkUtil.class );
  public static List<String> getAllAddresses() throws SocketException  {
    List<String> addrs = Lists.newArrayList( );
    Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces( );
    while( ifaces.hasMoreElements( ) ) {
      NetworkInterface iface = ifaces.nextElement( );
      for( InterfaceAddress iaddr : iface.getInterfaceAddresses( ) ) {
        InetAddress addr = iaddr.getAddress( );
        if( addr instanceof Inet4Address ) {
          if( !addr.isMulticastAddress( ) && !addr.isLoopbackAddress( ) && !addr.isLinkLocalAddress( ) && !addr.isSiteLocalAddress( ) && !"192.168.122.1".equals( addr.getHostAddress( ) ) ) {
            addrs.add( addr.getHostAddress( ) );
          }
        }
        if( addr instanceof Inet4Address ) {
          if( !addr.isMulticastAddress( ) && !addr.isLoopbackAddress( ) && !addr.isLinkLocalAddress( ) && !addrs.contains( addr.getHostAddress( ) ) && !"192.168.122.1".equals( addr.getHostAddress( ) ) ) {
            addrs.add( addr.getHostAddress( ) );
          }
        }
      }
    }
    return addrs;
  }

  public static boolean testReachability( String addr ) throws Exception {
    InetAddress inetAddr = Inet4Address.getByName( addr );
    return inetAddr.isReachable( 1000 );
  }

  public static boolean testLocal( String address ) {
    InetAddress addr;
    try {
      addr = InetAddress.getByName( address );
      List<String> addrs = Lists.newArrayList( );
      Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces( );
      while( ifaces.hasMoreElements( ) ) {
        NetworkInterface iface = ifaces.nextElement( );
        for( InterfaceAddress iaddr : iface.getInterfaceAddresses( ) ) {
          InetAddress ifaceAddr = iaddr.getAddress( );
          if( ifaceAddr.equals( addr ) ) {
            return true;
          }
        }
      }
      return addr.isAnyLocalAddress( );
    } catch ( Exception e ) {
      LOG.fatal( "Error getting address or network interface information.", e );
      return false;
    }
  }
  
  public static String tryToResolve( String address ) {
    InetAddress addr;
    try {
      addr = InetAddress.getByName( address );
      return addr.getHostAddress( );
    } catch ( UnknownHostException e ) {
      return address;
    }
  }

  public static boolean testGoodAddress( String address ) throws Exception {
    InetAddress addr = InetAddress.getByName( address );
    LOG.debug( addr + " site=" + addr.isSiteLocalAddress( ) );
    LOG.debug( addr + " any=" + addr.isAnyLocalAddress( ) );
    LOG.debug( addr + " loop=" + addr.isLoopbackAddress( ) );
    LOG.debug( addr + " link=" + addr.isLinkLocalAddress( ) );
    LOG.debug( addr + " multi=" + addr.isMulticastAddress( ) );
    return addr.isSiteLocalAddress( ) || ( !addr.isAnyLocalAddress( ) && !addr.isLoopbackAddress( ) && !addr.isLinkLocalAddress( ) && !addr.isMulticastAddress( ) );
  }

  
  public static void main( String[] args) throws Exception {
    for( String addr : NetworkUtil.getAllAddresses( ) ) {
      System.out.println( addr );
    }
    System.out.println("Testing if 192.168.7.8 is reachable: " + NetworkUtil.testReachability( "192.168.7.8" ) );
  }

}

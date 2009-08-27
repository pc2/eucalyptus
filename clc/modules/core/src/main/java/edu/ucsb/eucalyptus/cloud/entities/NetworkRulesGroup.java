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
 ******************************************************************************/
/*
 *
 * Author: chris grzegorczyk <grze@eucalyptus.com>
 */

package edu.ucsb.eucalyptus.cloud.entities;

import edu.ucsb.eucalyptus.cloud.Network;
import edu.ucsb.eucalyptus.msgs.PacketFilterRule;
import edu.ucsb.eucalyptus.util.EucalyptusProperties;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table( name = "network_group" )
@Cache( usage = CacheConcurrencyStrategy.READ_WRITE )
public class NetworkRulesGroup
{
  @Id
  @GeneratedValue
  @Column( name = "network_group_id" )
  private Long id = -1l;
  @Column( name = "network_group_name" )
  private String name;
  @Column( name = "network_group_description" )
  private String description;
  @OneToMany( cascade = CascadeType.ALL )
  @JoinTable(
      name = "network_group_has_rules",
      joinColumns = { @JoinColumn( name = "network_group_id" ) },
      inverseJoinColumns = @JoinColumn( name = "network_rule_id" )
  )
  @Cache( usage = CacheConcurrencyStrategy.READ_WRITE )
  private List<NetworkRule> networkRules = new ArrayList<NetworkRule>();

  public NetworkRulesGroup(){}

  public static NetworkRulesGroup getDefaultGroup() {
    return new NetworkRulesGroup( EucalyptusProperties.NETWORK_DEFAULT_NAME, "default group", new ArrayList<NetworkRule>() );
  }

  public NetworkRulesGroup( final String name )
  {
    this.name = name;
  }

  public NetworkRulesGroup( final String name, final String description, final List<NetworkRule> networkRules )
  {
    this.name = name;
    this.description = description;
    this.networkRules = networkRules;
  }

  public Long getId()
  {
    return id;
  }

  public String getName()
  {
    return name;
  }

  public void setName( final String name )
  {
    this.name = name;
  }

  public String getDescription()
  {
    return description;
  }

  public void setDescription( final String description )
  {
    this.description = description;
  }

  public List<NetworkRule> getNetworkRules()
  {
    return networkRules;
  }

  public void setNetworkRules( final List<NetworkRule> networkRules )
  {
    this.networkRules = networkRules;
  }

  public boolean equals( final Object o )
  {
    if ( this == o ) return true;
    if ( o == null || getClass() != o.getClass() ) return false;

    NetworkRulesGroup that = ( NetworkRulesGroup ) o;

    if ( !name.equals( that.name ) ) return false;

    return true;
  }

  public int hashCode()
  {
    return name.hashCode();
  }

  public Network getVmNetwork( String userName )
  {
    Network vmNetwork = new Network( userName, this.getName() );
    for ( NetworkRule networkRule : this.getNetworkRules() )
    {
      PacketFilterRule pfrule = new PacketFilterRule( userName, this.getName(), networkRule.getProtocol(), networkRule.getLowPort(), networkRule.getHighPort() );
      for ( IpRange cidr : networkRule.getIpRanges() )
        pfrule.getSourceCidrs().add( cidr.getValue() );
      for ( NetworkPeer peer : networkRule.getNetworkPeers() )
        pfrule.addPeer( peer.getUserQueryKey(), peer.getGroupName() );
      vmNetwork.getRules().add( pfrule );
    }
    return vmNetwork;
  }

}

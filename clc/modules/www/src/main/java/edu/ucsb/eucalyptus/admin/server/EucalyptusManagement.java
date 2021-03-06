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
 *
 * Author: Dmitrii Zagorodnov dmitrii@cs.ucsb.edu
 */

package edu.ucsb.eucalyptus.admin.server;

import com.eucalyptus.auth.CredentialProvider;
import com.eucalyptus.auth.NoSuchUserException;
import com.eucalyptus.auth.UserExistsException;
import com.eucalyptus.entities.NetworkRulesGroup;
import com.eucalyptus.network.NetworkGroupUtil;
import com.eucalyptus.util.DNSProperties;
import com.eucalyptus.util.EntityWrapper;
import com.eucalyptus.util.NetworkUtil;
import com.google.gwt.user.client.rpc.SerializableException;
import edu.ucsb.eucalyptus.admin.client.CloudInfoWeb;
import edu.ucsb.eucalyptus.admin.client.ImageInfoWeb;
import edu.ucsb.eucalyptus.admin.client.SystemConfigWeb;
import edu.ucsb.eucalyptus.admin.client.UserInfoWeb;
import edu.ucsb.eucalyptus.admin.client.WalrusInfoWeb;

import com.eucalyptus.util.EucalyptusCloudException;
import edu.ucsb.eucalyptus.cloud.entities.CertificateInfo;
import edu.ucsb.eucalyptus.cloud.entities.Counters;
import edu.ucsb.eucalyptus.cloud.entities.ImageInfo;
import edu.ucsb.eucalyptus.cloud.entities.SystemConfiguration;
import edu.ucsb.eucalyptus.cloud.entities.UserGroupInfo;
import edu.ucsb.eucalyptus.cloud.entities.UserInfo;
import edu.ucsb.eucalyptus.cloud.entities.WalrusInfo;
import edu.ucsb.eucalyptus.util.EucalyptusProperties;
import com.eucalyptus.util.StorageProperties;
import edu.ucsb.eucalyptus.util.UserManagement;
import com.eucalyptus.util.WalrusProperties;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EucalyptusManagement {

	private static Logger LOG = Logger.getLogger( EucalyptusManagement.class );

	public static UserInfoWeb fromServer( UserInfo source )
	{
		UserInfoWeb target = new UserInfoWeb();
		update( target, source );
		return target;
	}

	public static UserInfo fromClient( UserInfoWeb source )
	{
		UserInfo target = new UserInfo();
		update( target, source );
		return target;
	}

	public static void update( UserInfo target, UserInfo user )
	{
		target.setUserName( user.getUserName() );
		target.setRealName( user.getRealName() );
		target.setEmail( user.getEmail() );
		target.setBCryptedPassword( user.getBCryptedPassword() );
		target.setTelephoneNumber( user.getTelephoneNumber() );
		target.setAffiliation( user.getAffiliation() );
		target.setProjectDescription( user.getProjectDescription() );
		target.setProjectPIName( user.getProjectPIName() );
		target.setConfirmationCode( user.getConfirmationCode() );
		target.setCertificateCode( user.getCertificateCode() );
		target.setIsApproved( user.isApproved() );
		target.setIsConfirmed( user.isConfirmed() );
		target.setIsEnabled( user.isEnabled() );
		target.setIsAdministrator( user.isAdministrator() );
		target.setPasswordExpires( user.getPasswordExpires() );
		target.setTemporaryPassword( user.getTemporaryPassword() );
	}

	public static void update( UserInfoWeb target, UserInfo user )
	{
		target.setUserName( user.getUserName() );
		target.setRealName( user.getRealName() );
		target.setEmail( user.getEmail() );
		target.setBCryptedPassword( user.getBCryptedPassword() );
		target.setTelephoneNumber( user.getTelephoneNumber() );
		target.setAffiliation( user.getAffiliation() );
		target.setProjectDescription( user.getProjectDescription() );
		target.setProjectPIName( user.getProjectPIName() );
		target.setConfirmationCode( user.getConfirmationCode() );
		target.setCertificateCode( user.getCertificateCode() );
		target.setIsApproved( user.isApproved() );
		target.setIsConfirmed( user.isConfirmed() );
		target.setIsEnabled( user.isEnabled() );
		target.setIsAdministrator( user.isAdministrator() );
		target.setPasswordExpires( user.getPasswordExpires() );
		target.setTemporaryPassword( user.getTemporaryPassword() );
		String queryId = "uninitialized";
		String secretKey = "uninitialized";
		try {
			queryId = CredentialProvider.getQueryId( user.getUserName( ) );
			secretKey = CredentialProvider.getSecretKey( queryId );
		} catch ( GeneralSecurityException e ) {
			LOG.debug( e, e );
		}
		target.setQueryId( queryId );
		target.setSecretKey( secretKey );
	}

	public static void update( UserInfo target, UserInfoWeb user )
	{
		target.setUserName( user.getUserName() );
		target.setRealName( user.getRealName() );
		target.setEmail( user.getEmail() );
		target.setBCryptedPassword( user.getBCryptedPassword() );
		target.setTelephoneNumber( user.getTelephoneNumber() );
		target.setAffiliation( user.getAffiliation() );
		target.setProjectDescription( user.getProjectDescription() );
		target.setProjectPIName( user.getProjectPIName() );
		target.setConfirmationCode( user.getConfirmationCode() );
		target.setCertificateCode( user.getCertificateCode() );
		target.setIsApproved( user.isApproved() );
		target.setIsConfirmed( user.isConfirmed() );
		target.setIsEnabled( user.isEnabled() );
		target.setIsAdministrator( user.isAdministrator() );
		target.setPasswordExpires( user.getPasswordExpires() );
		target.setTemporaryPassword( user.getTemporaryPassword() );
	}

	public static ImageInfoWeb imageConvertToWeb ( ImageInfo source)
	{
		ImageInfoWeb target = new ImageInfoWeb();

		target.setId(source.getId());
		target.setImageId(source.getImageId());
		target.setImageLocation(source.getImageLocation());
		target.setImageState(source.getImageState());
		target.setImageOwnerId(source.getImageOwnerId());
		target.setArchitecture(source.getArchitecture());
		target.setImageType(source.getImageType());
		target.setKernelId(source.getKernelId());
		target.setRamdiskId(source.getRamdiskId());
		target.setPublic(source.getPublic());

		return target;
	}

	public static String getError( String message )
	{
		return "<html><title>HTTP/1.0 403 Forbidden</title><body><div align=\"center\"><p><h1>403: Forbidden</h1></p><p><img src=\"themes/active/logo.png\" /></p><p><h3 style=\"font-color: red;\">" + message + "</h3></p></div></body></html>";
	}

	/* TODO: for now 'pattern' is ignored and all users are returned */
	public static List <UserInfoWeb> getWebUsers (String pattern) throws SerializableException
	{
		UserInfo searchUser = new UserInfo(); /* empty => return all */
		EntityWrapper<UserInfo> dbWrapper = new EntityWrapper<UserInfo>();
		List<UserInfo> userList = dbWrapper.query( searchUser );

		List<UserInfoWeb> webUsersList = new ArrayList<UserInfoWeb>();
		for ( UserInfo u : userList)
			webUsersList.add(fromServer(u));
		dbWrapper.commit();
		return webUsersList;
	}

	/* TODO: for now 'pattern' is ignored and all images are returned */
	public static List <ImageInfoWeb> getWebImages (String pattern) throws SerializableException
	{
		ImageInfo searchImage = new ImageInfo(); /* empty => return all */
		EntityWrapper<ImageInfo> db = new EntityWrapper<ImageInfo>();
		List<ImageInfo> results= db.query( searchImage );
		List<ImageInfoWeb> imagesList = new ArrayList<ImageInfoWeb>();
		for ( ImageInfo i : results )
			imagesList.add(imageConvertToWeb(i));
		db.commit();
		return imagesList;
	}

	public static UserInfoWeb getWebUser( String userName ) throws SerializableException
	{
		EntityWrapper<UserInfo> dbWrapper = new EntityWrapper<UserInfo>();
		List<UserInfo> userList = dbWrapper.query( new UserInfo( userName ) );
		if ( userList.size() != 1 )
		{
			try {//TODO: temporary hack to support older user info objects
				if( "admin".equals( userName )) {
					UserInfo u = UserManagement.generateAdmin( );
					dbWrapper.add( u );
					UserGroupInfo allGroup = new UserGroupInfo( "all" );
					dbWrapper.getSession( ).persist( new Counters( ) );
					dbWrapper.commit( );
					return EucalyptusManagement.fromServer( u );
				} else {
					dbWrapper.rollback( );
					throw EucalyptusManagement.makeFault("User does not exist" );	        
				}
			} catch ( Exception e ) {
				dbWrapper.rollback( );
				throw EucalyptusManagement.makeFault("User does not exist" );
			}
		}
		dbWrapper.commit();
		return EucalyptusManagement.fromServer( userList.get( 0 ) );
	}

	public static UserInfoWeb getWebUserByEmail( String emailAddress ) throws SerializableException
	{
		UserInfo searchUser = new UserInfo( );
		searchUser.setEmail ( emailAddress );
		EntityWrapper<UserInfo> dbWrapper = new EntityWrapper<UserInfo>();
		List<UserInfo> userList = dbWrapper.query( searchUser );
		if ( userList.size() != 1 )
		{
			dbWrapper.rollback();
			throw EucalyptusManagement.makeFault("User does not exist" );
		}
		dbWrapper.commit();
		return EucalyptusManagement.fromServer( userList.get( 0 ) );
	}

	public static UserInfoWeb getWebUserByCode( String code ) throws SerializableException
	{
		UserInfo searchUser = new UserInfo( );
		searchUser.setConfirmationCode ( code );
		EntityWrapper<UserInfo> dbWrapper = new EntityWrapper<UserInfo>();
		List<UserInfo> userList = dbWrapper.query( searchUser );
		if ( userList.size() != 1 )
		{
			dbWrapper.rollback();
			throw EucalyptusManagement.makeFault("Invalid confirmation code" );
		}
		dbWrapper.commit();
		return EucalyptusManagement.fromServer( userList.get( 0 ) );
	}

	public static synchronized void addWebUser( UserInfoWeb webUser ) throws SerializableException
	{
		EntityWrapper<UserInfo> dbWrapper = new EntityWrapper<UserInfo>();
		List<UserInfo> userList = dbWrapper.query( new UserInfo( webUser.getUserName() ) );
		if ( userList.size() != 0 )
		{
			dbWrapper.rollback();
			throw EucalyptusManagement.makeFault("User already exists" );
		}

		//String hash = BCrypt.hashpw( webUser.getBCryptedPassword(), BCrypt.gensalt() );
		//webUser.setBCryptedPassword( hash );
		//webUser.setIsAdministrator( false );
		//webUser.setIsApproved( false );
		//webUser.setIsEnabled( false );

		// TODO: add web user properly, with all keys and certs generated, too
		webUser.setConfirmationCode( UserManagement.generateConfirmationCode( webUser.getUserName() ) );
		webUser.setCertificateCode( UserManagement.generateCertificateCode( webUser.getUserName() ) );

		webUser.setSecretKey( UserManagement.generateSecretKey( webUser.getUserName() ) );
		webUser.setQueryId( UserManagement.generateQueryId( webUser.getUserName() ));

		UserInfo newUser = EucalyptusManagement.fromClient( webUser );
		newUser.setReservationId( 0l );
		try {
			NetworkGroupUtil.createUserNetworkRulesGroup( newUser.getUserName( ), NetworkRulesGroup.NETWORK_DEFAULT_NAME, "default group" );
		} catch ( EucalyptusCloudException e1 ) {
			LOG.debug( e1, e1 );
		}

		dbWrapper.add( newUser );
		dbWrapper.commit();

		try {//FIXME: fix this nicely
			CredentialProvider.addUser(newUser.getUserName( ),newUser.isAdministrator( ));
		} catch ( UserExistsException e ) {
			LOG.error(e);
		}
	}

	private static SerializableException makeFault(String message)
	{
		SerializableException e = new SerializableException( message );
		LOG.error(e);
		return e;
	}

	public static void deleteWebUser( UserInfoWeb webUser ) throws SerializableException
	{
		String userName = webUser.getUserName();
		deleteUser( userName );
	}

	public static void deleteUser( String userName ) throws SerializableException
	{
		EntityWrapper<UserInfo> db = new EntityWrapper<UserInfo>();
		List<UserInfo> userList = db.query( new UserInfo( userName )  );
		if ( userList.size() != 1 )
		{
			db.rollback();
			throw EucalyptusManagement.makeFault("User already exists" );
		}
		db.delete( userList.get(0) );
		db.commit();
		try {
			CredentialProvider.deleteUser(userName);
		} catch ( NoSuchUserException e ) {
			LOG.error(e);
			throw EucalyptusManagement.makeFault( "Unable to delete user" );
		}
	}

	public static void commitWebUser( UserInfoWeb webUser ) throws SerializableException
	{
		UserInfo user = fromClient( webUser );
		commitUser( user );
	}

	public static void commitUser( UserInfo user ) throws SerializableException
	{
		UserInfo searchUser = new UserInfo( user.getUserName() );
		EntityWrapper<UserInfo> db = new EntityWrapper<UserInfo>();
		List<UserInfo> userList = db.query( searchUser );
		UserInfo target = userList.get( 0 );
		if ( userList.size() != 1 )
		{
			db.rollback();
			throw EucalyptusManagement.makeFault( "User does not exist" );
		}
		update( target, user );
		try {
			CredentialProvider.updateUser(user.getUserName(), user.isEnabled());
		} catch ( NoSuchUserException e ) {
			db.rollback();
			LOG.error(e);
			throw EucalyptusManagement.makeFault( "Unable to update user" );
		}
		db.commit();
	}

	public static String getAdminEmail() throws SerializableException
	{
		UserInfo searchUser = new UserInfo();
		searchUser.setIsAdministrator( true );
		EntityWrapper<UserInfo> db = new EntityWrapper<UserInfo>();
		List<UserInfo> userList = db.query( searchUser );
		if ( userList.size() < 1 || userList.isEmpty() )
		{
			db.rollback();
			throw EucalyptusManagement.makeFault("Administrator account not found" );
		}

		UserInfo first = userList.get( 0 );
		String addr = first.getEmail();
		if (addr==null || addr.equals("")) {
			db.rollback();
			throw EucalyptusManagement.makeFault( "Email address is not set" );
		}
		db.commit();
		return addr;

		//return Configuration.getConfiguration().getAdminEmail();
	}

	public static void deleteImage(String imageId)
	throws SerializableException
	{
		ImageInfo searchImg = new ImageInfo( );
		searchImg.setImageId( imageId );
		EntityWrapper<ImageInfo> db = new EntityWrapper<ImageInfo>();
		List<ImageInfo> imgList= db.query( searchImg );

		if ( imgList.size() > 0 && !imgList.isEmpty() )
		{
			ImageInfo foundimgSearch = imgList.get( 0 );
			foundimgSearch.setImageState( "deregistered" );
			db.commit();
		}
		else
		{
			db.rollback();
			throw EucalyptusManagement.makeFault ("Specified image was not found, sorry.");
		}
	}
	public static void disableImage(String imageId)
	throws SerializableException
	{
		ImageInfo searchImg = new ImageInfo( );
		searchImg.setImageId( imageId );
		EntityWrapper<ImageInfo> db = new EntityWrapper<ImageInfo>();
		List<ImageInfo> imgList= db.query( searchImg );

		if ( imgList.size() > 0 && !imgList.isEmpty() )
		{
			ImageInfo foundimgSearch = imgList.get( 0 );
			foundimgSearch.setImageState( "deregistered" );
			db.commit();
		}
		else
		{
			db.rollback();
			throw EucalyptusManagement.makeFault ("Specified image was not found, sorry.");
		}
	}
	public static void enableImage(String imageId)
	throws SerializableException
	{
		ImageInfo searchImg = new ImageInfo( );
		searchImg.setImageId( imageId );
		EntityWrapper<ImageInfo> db = new EntityWrapper<ImageInfo>();
		List<ImageInfo> imgList= db.query( searchImg );

		if ( imgList.size() > 0 && !imgList.isEmpty() )
		{
			ImageInfo foundimgSearch = imgList.get( 0 );
			foundimgSearch.setImageState( "available" );
			db.commit();
		}
		else
		{
			db.rollback();
			throw EucalyptusManagement.makeFault ("Specified image was not found, sorry.");
		}
	}

	public static SystemConfigWeb getSystemConfig() throws SerializableException
	{
		EntityWrapper<SystemConfiguration> db = new EntityWrapper<SystemConfiguration>();
		SystemConfiguration sysConf = EucalyptusProperties.getSystemConfiguration();
		return new SystemConfigWeb( 
				sysConf.getDefaultKernel(),
				sysConf.getDefaultRamdisk(),
				sysConf.getMaxUserPublicAddresses(),
				sysConf.isDoDynamicPublicAddresses(),
				sysConf.getSystemReservedPublicAddresses(),
				sysConf.getZeroFillVolumes(),
				sysConf.getDnsDomain(),
				sysConf.getNameserver(),
				sysConf.getNameserverAddress(),
				sysConf.getCloudHost( ));
	}

	public static void setSystemConfig( final SystemConfigWeb systemConfig )
	{
		EntityWrapper<SystemConfiguration> db = new EntityWrapper<SystemConfiguration>();
		try
		{
			SystemConfiguration sysConf = db.getUnique( new SystemConfiguration() );
			sysConf.setCloudHost( systemConfig.getCloudHost() );
			sysConf.setDefaultKernel( systemConfig.getDefaultKernelId() );
			sysConf.setDefaultRamdisk( systemConfig.getDefaultRamdiskId() );

			sysConf.setDnsDomain(systemConfig.getDnsDomain());
			sysConf.setNameserver(systemConfig.getNameserver());
			sysConf.setNameserverAddress(systemConfig.getNameserverAddress());
			sysConf.setMaxUserPublicAddresses( systemConfig.getMaxUserPublicAddresses() );
			sysConf.setDoDynamicPublicAddresses( systemConfig.isDoDynamicPublicAddresses() );
			sysConf.setSystemReservedPublicAddresses( systemConfig.getSystemReservedPublicAddresses() );
			sysConf.setZeroFillVolumes(systemConfig.getZeroFillVolumes());
			db.commit();
			DNSProperties.update();
		}
		catch ( EucalyptusCloudException e )
		{
			db.add( new SystemConfiguration(
					systemConfig.getDefaultKernelId(),
					systemConfig.getDefaultRamdiskId(),
					systemConfig.getMaxUserPublicAddresses(),
					systemConfig.isDoDynamicPublicAddresses(),
					systemConfig.getSystemReservedPublicAddresses(),
					systemConfig.getZeroFillVolumes(),
					systemConfig.getDnsDomain(),
					systemConfig.getNameserver(),
					systemConfig.getNameserverAddress(),
					systemConfig.getCloudHost( )));
			db.commit();
			DNSProperties.update();
		}
	}

	private static String getExternalIpAddress ()
	{
		String ipAddr = null;
		HttpClient httpClient = new HttpClient();
		// Use Rightscale's "whoami" service
		GetMethod method = new GetMethod("https://my.rightscale.com/whoami?api_version=1.0&cloud=0");
		Integer timeoutMs = new Integer(3 * 1000); // TODO: is this working?
		method.getParams().setSoTimeout(timeoutMs);

		try {
			httpClient.executeMethod(method);
			String str = "";
			InputStream in = method.getResponseBodyAsStream();
			byte[] readBytes = new byte[1024];
			int bytesRead = -1;
			while((bytesRead = in.read(readBytes)) > 0) {
				str += new String(readBytes, 0, bytesRead);
			}
			Matcher matcher = Pattern.compile(".*your ip is (.*)").matcher(str);
			if (matcher.find()) {
				ipAddr = matcher.group(1);
			}

		} catch (MalformedURLException e) {
			LOG.warn ("Malformed URL exception: " + e.getMessage());
			e.printStackTrace();

		} catch (IOException e) {
			LOG.warn ("I/O exception: " + e.getMessage());
			e.printStackTrace();

		} finally {
			method.releaseConnection();
		}

		return ipAddr;
	}

	public static CloudInfoWeb getCloudInfo (boolean setExternalHostPort) throws SerializableException
	{
		String cloudRegisterId = null;
	    cloudRegisterId = EucalyptusProperties.getSystemConfiguration().getRegistrationId();
		CloudInfoWeb cloudInfo = new CloudInfoWeb();
		cloudInfo.setInternalHostPort (EucalyptusProperties.getInternalIpAddress() + ":8443");
		if (setExternalHostPort) {
			String ipAddr = getExternalIpAddress();
			if (ipAddr!=null) {
				cloudInfo.setExternalHostPort ( ipAddr + ":8443");
			}
		}
		cloudInfo.setServicePath ("/register"); // TODO: what is the actual cloud registration service?
		cloudInfo.setCloudId ( cloudRegisterId ); // TODO: what is the actual cloud registration ID?
		return cloudInfo;
	}

}

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
package edu.ucsb.eucalyptus.admin.client;

import com.google.gwt.user.client.rpc.AsyncCallback;
import com.google.gwt.user.client.ui.*;

import edu.ucsb.eucalyptus.admin.client.ClusterInfoTable.DeleteCallback;
import edu.ucsb.eucalyptus.admin.client.SystemConfigTable.ChangeCallback;
import edu.ucsb.eucalyptus.admin.client.SystemConfigTable.FocusHandler;

import java.util.ArrayList;
import java.util.List;

// dmitrii TODO: remove commented out lines once the CSS-based design is confirmed

public class WalrusInfoTable extends VerticalPanel implements ClickListener {

	private static int maxWalruses = 1; // TODO: bump this up once we can do more than 1
	private static Label noWalrusesLabel = new Label();
	private static Label statusLabel = new Label();
	private Grid grid = new Grid ();
	private Button add_button = new Button ( "Register Walrus", this );
	private static HTML hint = new HTML ();
	private List<WalrusInfoWeb> walrusList = new ArrayList<WalrusInfoWeb>();
	private static String sessionId;
	private static String warningMessage = "Note: registering Walrus requires synchronization of keys among all nodes, which cannot be done through this interface.  See documentation for details.";

	public WalrusInfoTable(String sessionId)
	{
		this.sessionId = sessionId;
		this.setStyleName("euca-config-component");
		this.setSpacing (2);
		this.setVerticalAlignment(HasVerticalAlignment.ALIGN_MIDDLE);
//		this.setHorizontalAlignment(HasHorizontalAlignment.ALIGN_CENTER);
		Label walrusesHeader = new Label( "Walrus Configuration:" );
		walrusesHeader.setStyleName ( "euca-section-header" );
		this.add ( walrusesHeader );
		this.noWalrusesLabel.setText ("No Walrus hosts registered");
		this.noWalrusesLabel.setStyleName ("euca-greeting-disabled");
		HorizontalPanel grid_and_hint = new HorizontalPanel ();
		grid_and_hint.add ( this.grid );
		grid_and_hint.add ( this.hint );
		this.hint.setWidth ("100");
		this.add ( grid_and_hint );
		HorizontalPanel hpanel = new HorizontalPanel ();
		hpanel.setSpacing (2);
		hpanel.add ( add_button );
		hpanel.add ( new Button( "Save Walrus configuration", new SaveCallback( this ) ) );
		hpanel.add ( this.statusLabel );
//		this.statusLabel.setWidth ("250");
		this.statusLabel.setText ("");
		this.statusLabel.setStyleName ("euca-greeting-pending");
		this.add ( hpanel );
		rebuildTable();
		EucalyptusWebBackend.App.getInstance().getWalrusList(
				this.sessionId, new GetWalrusListCallback( this ) );
	}

	public void onClick( final Widget widget ) // Register walrus button
	{
		this.walrusList.add (new WalrusInfoWeb("Walrus", "host", 8773, "/var/lib/eucalyptus/bukkits", 5, 5120l, 30720L, 50)); //these values are just defaults
		this.rebuildTable();
		this.statusLabel.setText ("Unsaved changes");
		this.statusLabel.setStyleName ("euca-greeting-warning");
	}

	private void rebuildTable()
	{
		if (this.walrusList.isEmpty()) {
			this.grid.setVisible (false);
			this.noWalrusesLabel.setVisible (true);
			this.add_button.setEnabled (true);

		} else {
			this.noWalrusesLabel.setVisible (false);
			this.grid.clear ();
			this.grid.resize ( this.walrusList.size(), 1 );
			this.grid.setVisible (true);
			this.grid.setStyleName( "euca-table" );
			this.grid.setCellPadding( 2 );

			int row = 0;
			for ( WalrusInfoWeb w : this.walrusList ) {
				/*// big yellow block looks kinda weird
				if ( ( row % 2 ) == 1 ) {
					this.grid.getRowFormatter().setStyleName( row, "euca-table-even-row" );
				} else {
					this.grid.getRowFormatter().setStyleName( row, "euca-table-odd-row" );
				}*/
				this.grid.setWidget (row, 0, addWalrusEntry (row++, w));
			}

			if ( row >= maxWalruses ) {
				this.add_button.setEnabled (false);
			} else {
				this.add_button.setEnabled (true);
			}
		}
	}

	private Grid addWalrusEntry ( int row, WalrusInfoWeb walrusInfo)
	{
		Grid g = new Grid (6, 2);
		g.setStyleName( "euca-table" );
		g.setCellPadding( 4 );

		int i = 0; // row 1
		g.setWidget( i, 0, new Label( "Walrus host:" ) );
		g.getCellFormatter().setHorizontalAlignment(i, 0, HasHorizontalAlignment.ALIGN_RIGHT);
		HorizontalPanel p = new HorizontalPanel ();
		p.setSpacing(0);
		g.setWidget( i, 1, p );
		final TextBox walrusHost_box = new TextBox();
		walrusHost_box.addChangeListener (new ChangeCallback (this, row));
		walrusHost_box.setVisibleLength(35);
		walrusHost_box.setText (walrusInfo.getHost());
		p.add (walrusHost_box);
		p.add (new Button ("Deregister", new DeleteCallback( this, row )));
		
		i++; // next row
		g.setWidget( i, 0, new Label( "Buckets path:" ) );
		g.getCellFormatter().setHorizontalAlignment(i, 0, HasHorizontalAlignment.ALIGN_RIGHT);
		final TextBox walrusPath_box = new TextBox();
		walrusPath_box.addChangeListener (new ChangeCallback (this, row));
		walrusPath_box.setVisibleLength(35);
		walrusPath_box.setText (walrusInfo.getBucketsRootDirectory());
		walrusPath_box.addFocusListener (new FocusHandler (hint, "Warning! Changing the path may make inaccessible any content uploaded to the old path, including images, kernels, and ramdisks."));
		g.setWidget( i, 1, walrusPath_box );

		i++; // next row
		final TextBox maxBuckets_box = new TextBox();
		maxBuckets_box.addChangeListener (new ChangeCallback (this, row));
		maxBuckets_box.setVisibleLength(10);
		maxBuckets_box.setText (""+walrusInfo.getMaxBucketsPerUser());
		g.setWidget( i, 0, maxBuckets_box);
		g.getCellFormatter().setHorizontalAlignment(i, 0, HasHorizontalAlignment.ALIGN_RIGHT);
		g.setWidget( i, 1, new Label( "Maximum buckets per user" ));

		i++; // next row
		final TextBox maxBucketSize_box = new TextBox();
		maxBucketSize_box.addChangeListener (new ChangeCallback (this, row));
		maxBucketSize_box.setVisibleLength(10);
		maxBucketSize_box.setText (""+walrusInfo.getMaxBucketSizeInMB());
		maxBucketSize_box.addFocusListener (new FocusHandler (hint, "You are urged to consult the documentation before changing the default value!"));
		g.setWidget( i, 0, maxBucketSize_box);
		g.getCellFormatter().setHorizontalAlignment(i, 0, HasHorizontalAlignment.ALIGN_RIGHT);
		g.setWidget( i, 1, new Label ("MB maximum bucket size"));

		i++; // next row
		final TextBox maxCacheSize_box = new TextBox();
		maxCacheSize_box.addChangeListener (new ChangeCallback (this, row));
		maxCacheSize_box.setVisibleLength(10);
		maxCacheSize_box.setText ("" + walrusInfo.getMaxCacheSizeInMB());
		maxCacheSize_box.addFocusListener (new FocusHandler (hint, "You are urged to consult the documentation before changing the default value!"));
		g.setWidget( i, 0, maxCacheSize_box );
		g.getCellFormatter().setHorizontalAlignment(i, 0, HasHorizontalAlignment.ALIGN_RIGHT);
		g.setWidget( i, 1, new Label ("MB of disk are reserved for the image cache"));		

		i++; // next row
		final TextBox totalSnapshots_box = new TextBox();
		totalSnapshots_box.addChangeListener (new ChangeCallback (this, row));
		totalSnapshots_box.setVisibleLength(10);
		totalSnapshots_box.setText ("" + walrusInfo.getSnapshotsTotalInGB());
		totalSnapshots_box.addFocusListener (new FocusHandler (hint, "You are urged to consult the documentation before changing the default value!"));
		g.setWidget( i, 0, totalSnapshots_box );
		g.getCellFormatter().setHorizontalAlignment(i, 0, HasHorizontalAlignment.ALIGN_RIGHT);
		g.setWidget( i, 1, new Label ("GB of disk are reserved for snapshots"));

		return g;
	}

	public List<WalrusInfoWeb> getWalrusList()
	{
		return walrusList;
	}

	public void setWalrusList ( final List<WalrusInfoWeb> walrusList )
	{
		this.walrusList = walrusList;
	}

	public void updateRow (int row)
	{
		WalrusInfoWeb walrus = this.walrusList.get (row);
		Grid g = (Grid)this.grid.getWidget(row, 0);
		HorizontalPanel p = (HorizontalPanel)g.getWidget(0, 1);
		walrus.setHost                 (((TextBox)p.getWidget(0)).getText());
		walrus.setBucketsRootDirectory (((TextBox)g.getWidget(1, 1)).getText());		
		walrus.setMaxBucketsPerUser    (Integer.parseInt (((TextBox)g.getWidget(2, 0)).getText()));
		walrus.setMaxBucketSizeInMB    (Long.parseLong   (((TextBox)g.getWidget(3, 0)).getText()));
		walrus.setMaxCacheSizeInMB     (Long.parseLong   (((TextBox)g.getWidget(4, 0)).getText()));
		walrus.setSnapshotsTotalInGB   (Integer.parseInt (((TextBox)g.getWidget(5, 0)).getText()));
	}

	public void MarkCommitted ()
	{
		for ( WalrusInfoWeb walrus : this.walrusList ) {
			walrus.setCommitted ();
		}
	}

	class ChangeCallback implements ChangeListener, ClickListener {
		private WalrusInfoTable parent;
		private int row;

		ChangeCallback ( final WalrusInfoTable parent, final int row )
		{
			this.parent = parent;
			this.row = row;
		}

		public void onChange (Widget sender)
		{
			this.parent.updateRow (this.row);
			this.parent.statusLabel.setText ("Unsaved changes");
			this.parent.statusLabel.setStyleName ("euca-greeting-warning");
		}

		public void onClick (Widget sender)
		{
			this.parent.updateRow (this.row);
			this.parent.statusLabel.setText ("Unsaved changes");
			this.parent.statusLabel.setStyleName ("euca-greeting-warning");
		}
	}

	class DeleteCallback implements ClickListener {

		private WalrusInfoTable parent;
		private int row;

		DeleteCallback( final WalrusInfoTable parent, final int row )
		{
			this.parent = parent;
			this.row = row;
		}

		public void onClick( final Widget widget )
		{
			this.parent.walrusList.remove (this.row);
			this.parent.rebuildTable();
			this.parent.statusLabel.setText ("Unsaved changes");
			this.parent.statusLabel.setStyleName ("euca-greeting-warning");
		}
	}

	class GetWalrusListCallback implements AsyncCallback {

		private WalrusInfoTable parent;

		GetWalrusListCallback( final WalrusInfoTable parent )
		{
			this.parent = parent;
		}

		public void onFailure( final Throwable throwable )
		{
			this.parent.statusLabel.setText ("Failed to contact server!");
			this.parent.statusLabel.setStyleName ("euca-greeting-error");
		}

		public void onSuccess( final Object o )
		{
			List<WalrusInfoWeb> newWalrusList = (List<WalrusInfoWeb>) o;
			this.parent.statusLabel.setText ("Walrus configuration up to date");
			this.parent.statusLabel.setStyleName ("euca-greeting-disabled");
			this.parent.walrusList = newWalrusList;
			this.parent.MarkCommitted();
			this.parent.rebuildTable();
		}
	}

	class SaveCallback implements AsyncCallback, ClickListener {

		private WalrusInfoTable parent;

		SaveCallback( final WalrusInfoTable parent )
		{
			this.parent = parent;
		}

		public void onClick( final Widget widget )
		{
			this.parent.statusLabel.setText ("Saving...");
			this.parent.statusLabel.setStyleName ("euca-greeting-pending");
			EucalyptusWebBackend.App.getInstance().setWalrusList(
					this.parent.sessionId, this.parent.walrusList, this );
		}

		public void onFailure( final Throwable throwable )
		{
			this.parent.statusLabel.setText ("Failed to save! (Check hostname and path.)");
			this.parent.statusLabel.setStyleName ("euca-greeting-error");
		}

		public void onSuccess( final Object o )
		{
			this.parent.statusLabel.setText ("Saved Walrus configuration to server");
			this.parent.statusLabel.setStyleName ("euca-greeting-disabled");
			this.parent.MarkCommitted ();
			this.parent.rebuildTable(); // so the committed ones show up
		}
	}

	class FocusHandler implements FocusListener {
		private HTML parent;
		private String message;

		FocusHandler (final HTML parent, String message)
		{
			this.parent = parent;
			this.message = message;
		}
		public void onLostFocus (Widget sender)
		{
			this.parent.setHTML ("");
			this.parent.setStyleName ("euca-text");
		}
		public void onFocus (Widget sender)
		{
			this.parent.setHTML (message);
			this.parent.setStyleName ("euca-error-hint");
		}
	}
}

/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mui;

import javax.swing.SwingWorker;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import muicore.ManticoreUIGrpc;
import muicore.ManticoreUIGrpc.ManticoreUIBlockingStub;
import muicore.ManticoreUIGrpc.ManticoreUIStub;
import muicore.MUICore.StopServerRequest;

// @formatter:off
@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = "MUI",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Manticore User Interface",
    description =
        "GUI Plugin that allows users to easily interact with and view progress of the Manticore symbolic execution engine.")
// @formatter:on
public class MUIPlugin extends ProgramPlugin {

	public static MUISetupProvider setup;
	public static MUILogProvider log;
	public static MUIPopupMenu popup;
	public static MUIStateListProvider stateList;

	private String MUICoreServerPath;
	public static ManticoreUIBlockingStub blockingMUICoreStub;
	public static ManticoreUIStub asyncMUICoreStub;

	private DockingAction showSetup;
	private DockingAction showLog;
	private DockingAction showStateList;

	/**
	 * The main extension constructor, initializes the plugin's components and sets up the "MUI" MenuBar tab.
	 * @throws Exception 
	 */
	public MUIPlugin(PluginTool tool) throws Exception {
		super(tool, true, true);

		startMUICoreServer();
		initMUICoreStubs();

		String pluginName = getName();
		log = new MUILogProvider(tool, pluginName);
		popup = new MUIPopupMenu(tool, pluginName);
		stateList = new MUIStateListProvider(tool, pluginName);
		setup = new MUISetupProvider(tool, pluginName);

		showSetup = new DockingAction("Run Manticore", pluginName) {

			@Override
			public void actionPerformed(ActionContext context) {
				setup.setVisible(true);
			}
		};

		showLog = new DockingAction("Show Log", pluginName) {

			@Override
			public void actionPerformed(ActionContext context) {
				log.setVisible(true);
			}
		};

		showStateList = new DockingAction("Show State List", pluginName) {

			@Override
			public void actionPerformed(ActionContext context) {
				stateList.setVisible(true);
			}

		};

		showSetup.setMenuBarData(new MenuData(new String[] { "MUI", "Run Manticore" }));
		showLog.setMenuBarData(new MenuData(new String[] { "MUI", "Show Log" }));
		showStateList.setMenuBarData(new MenuData(new String[] { "MUI", "Show State List" }));

		tool.addAction(showSetup);
		tool.addAction(showLog);
		tool.addAction(showStateList);
	}

	/**
	 * Starts the MUICore server using the muicore_server binary included in the extension.
	 * 
	 * Should eventually be optimized such that it's created only when needed, and automatically  
	 * destroys after a set period of inactivity.
	 * @throws Exception
	 */

	public void startMUICoreServer() throws Exception {
		try {
			if (!Application.isInitialized()) {
				Application.initializeApplication(
					new GhidraApplicationLayout(), new ApplicationConfiguration());
			}
			MUICoreServerPath = Application.getOSFile("muicore_server").getCanonicalPath();
		}
		catch (Exception e) {
			throw e;
		}

		SwingWorker sw =
			new SwingWorker() {

				@Override
				protected Object doInBackground() throws Exception {
					ProcessBuilder pb = new ProcessBuilder(MUICoreServerPath);
					Process p = pb.start();
					Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {

						@Override
						public void run() {
							blockingMUICoreStub.stopServer(StopServerRequest.newBuilder().build());
						}

					}));
					return null;
				}
			};
		sw.execute();
	}

	/**
	 * Initializes the gRPC Stub classes that allows the plugin to communicate with the MUICore server as a client.
	 */
	public void initMUICoreStubs() {
		ManagedChannel channel =
			ManagedChannelBuilder.forTarget("localhost:50010").usePlaintext().build();
		blockingMUICoreStub = ManticoreUIGrpc.newBlockingStub(channel);
		asyncMUICoreStub = ManticoreUIGrpc.newStub(channel);
	}

	@Override
	protected void programActivated(Program p) {
		setup.setProgram(p);
		popup.setProgram(p);
	}
}

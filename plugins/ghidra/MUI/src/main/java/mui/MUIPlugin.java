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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

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

	public MUISetupProvider provider;
	public MUILogProvider log;
	public MUIPopupMenu popup;
	public MUIStateListProvider stateList;

	private DockingAction showSetup;
	private DockingAction showLog;
	private DockingAction showStateList;

	/**
	 * The main extension constructor, initializes the plugin's components and sets up the "MUI" MenuBar tab.
	 */
	public MUIPlugin(PluginTool tool) {
		super(tool, true, true);
		String pluginName = getName();
		log = new MUILogProvider(tool, pluginName);
		popup = new MUIPopupMenu(tool, pluginName);
		stateList = new MUIStateListProvider(tool, pluginName);
		provider = new MUISetupProvider(tool, pluginName, log, stateList);

		showSetup = new DockingAction("Run Manticore", pluginName) {

			@Override
			public void actionPerformed(ActionContext context) {
				provider.setVisible(true);
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

	@Override
	protected void programActivated(Program p) {
		provider.setProgram(p);
		popup.setProgram(p);
	}
}

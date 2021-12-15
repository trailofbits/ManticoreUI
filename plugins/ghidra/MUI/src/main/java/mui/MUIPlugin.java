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

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

/** TODO: Provide class-level documentation that describes what this plugin does. */
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

	public MUIPlugin(PluginTool tool) {
		super(tool, true, true);
		String pluginName = getName();
		log = new MUILogProvider(tool, pluginName);
		provider = new MUISetupProvider(tool, pluginName, log);
	}

	@Override
	protected void programActivated(Program p) {
		provider.setProgram(p);
	}
}

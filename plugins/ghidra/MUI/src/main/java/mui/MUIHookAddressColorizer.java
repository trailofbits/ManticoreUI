package mui;

import java.awt.Color;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.program.model.address.Address;
import muicore.MUICore.Hook.HookType;

public class MUIHookAddressColorizer {

	/**
	 * Sets color in the Listing component for the specified address.
	 * @param address The address to set color of in the Disassembly Listing.
	 * @param hookType The HookType of the hook at the address being colorized. 
	 */
	public static void setColor(Address address, HookType hookType) {
		ColorizingService service = MUIPlugin.pluginTool.getService(ColorizingService.class);
		int tid = MUIPlugin.program.startTransaction("setColor");
		Color toSet = Color.BLUE;
		switch (hookType) {
			case FIND:
				toSet = Color.GREEN;
				break;
			case AVOID:
				toSet = Color.RED;
				break;
			case CUSTOM:
				toSet = new Color(120, 150, 255);
				break;
			default:
				break;
		}

		service.setBackgroundColor(address, address, toSet);
		MUIPlugin.program.endTransaction(tid, true);
	}

	/**
	 * Clears color from the Listing component for the specified address.
	 * @param address The address to clear color from.
	 */
	public static void clearColor(Address address) {
		ColorizingService service = MUIPlugin.pluginTool.getService(ColorizingService.class);
		int tid = MUIPlugin.program.startTransaction("unsetColor");
		service.clearBackgroundColor(address, address);
		MUIPlugin.program.endTransaction(tid, true);
	}

}

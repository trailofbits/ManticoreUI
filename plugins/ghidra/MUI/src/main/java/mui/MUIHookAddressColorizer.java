package mui;

import java.awt.Color;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.program.model.address.Address;
import muicore.MUICore.Hook.HookType;

public class MUIHookAddressColorizer {

	public static final Color FIND_HIGHLIGHT_COLOR = Color.GREEN;
	public static final Color AVOID_HIGHLIGHT_COLOR = Color.RED;
	public static final Color CUSTOM_HIGHLIGHT_COLOR = new Color(120, 150, 255);

	/**
	 * Sets color in the Listing component for the specified address.
	 * @param address The address to set color of in the Disassembly Listing.
	 * @param hookType The HookType of the hook at the address being colorized, which determines the highlight color. 
	 */
	public static void setColor(Address address, HookType hookType) {
		ColorizingService service = MUIPlugin.pluginTool.getService(ColorizingService.class);
		int tid = MUIPlugin.program.startTransaction("setColor");
		Color toSet = Color.WHITE;
		switch (hookType) {
			case FIND:
				toSet = FIND_HIGHLIGHT_COLOR;
				break;
			case AVOID:
				toSet = AVOID_HIGHLIGHT_COLOR;
				break;
			case CUSTOM:
				toSet = CUSTOM_HIGHLIGHT_COLOR;
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

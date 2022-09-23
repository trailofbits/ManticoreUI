package mui;

import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import ghidra.program.model.address.Address;
import manticore_server.ManticoreServerOuterClass.Hook.HookType;

public class MUIHookCodeDialogLauncher {

	static final String DEFAULT_CUSTOM_FUNCTION =
		"global m, addr\ndef hook(state):\n    pass\nm.hook(addr)(hook)";
	static final String DEFAULT_GLOBAL_FUNCTION =
		"global m\ndef hook(state):\n    pass\nm.hook(None)(hook)";

	/**
	 * Shows dialog which allows a user to create a new custom hook.
	 * @param address The Address that the hook should be set at.
	 */
	public static void showCreateCustom(Address address) {
		JTextArea textArea = new JTextArea(DEFAULT_CUSTOM_FUNCTION);
		int result = JOptionPane.showConfirmDialog(null, new JScrollPane(textArea),
			"Create Custom Hook at " + address.toString(),
			JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		if (result == JOptionPane.OK_OPTION) {
			MUIPlugin.setup.setupHookList.addHook(new MUIHookUserObject(HookType.CUSTOM,
				address, textArea.getText()));
			MUIHookAddressColorizer.setColor(address, HookType.CUSTOM);
		}
	}

	/**
	 * Shows dialog which allows a user to create a new global hook.
	 */
	public static void showCreateGlobal() {
		JTextArea textArea = new JTextArea(DEFAULT_GLOBAL_FUNCTION);
		int result = JOptionPane.showConfirmDialog(null, new JScrollPane(textArea),
			"Create Global Hook",
			JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		if (result == JOptionPane.OK_OPTION) {
			MUIPlugin.setup.setupHookList
					.addHook(new MUIHookUserObject(HookType.GLOBAL, textArea.getText()));
		}
	}

	/**
	 * Shows Dialog which allows a user to edit the function text of an existing custom or global hook.
	 * @param hookObject The hookObject which is being edited.
	 */
	public static void showEdit(MUIHookUserObject hookObject) {
		switch (hookObject.type) {
			case CUSTOM:
			case GLOBAL:
				JTextArea textArea = new JTextArea(hookObject.func_text);
				int result = JOptionPane.showConfirmDialog(null, new JScrollPane(textArea),
					hookObject.type == HookType.CUSTOM
							? "Edit Custom Hook at " + hookObject.address.toString()
							: "Edit Global Hook",
					JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
				if (result == JOptionPane.OK_OPTION) {
					hookObject.func_text = textArea.getText();
				}
			default:
				break;
		}
	}
}

package mui;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import ghidra.program.model.address.Address;
import muicore.MUICore.Hook;
import muicore.MUICore.Hook.HookType;
import muicore.MUICore.Hook.Builder;

public class MUIHookUserObject {
	public HookType type;
	public String name;
	public Address address;
	public String func_text;

	public MUIHookUserObject(HookType type, Address address, String func_text) {
		this.type = type;
		this.name = address.toString();
		this.address = address;
		this.func_text = func_text;
	}

	public MUIHookUserObject(HookType type, String func_text) {
		this.type = type;
		this.name = "Global " + ZonedDateTime.now(ZoneId.systemDefault())
				.format(DateTimeFormatter.ofPattern("HH:mm:ss"));
		this.func_text = func_text;
	}

	public Hook toMUIHook() {
		Builder b = Hook.newBuilder().setType(type);
		switch (type) {
			case FIND:
			case AVOID:
				b.setAddress(
					Long.parseLong(address.toString(), 16));
				break;
			case CUSTOM:
				b.setAddress(
					Long.parseLong(address.toString(), 16));
			case GLOBAL:
				b.setFuncText(func_text);
				break;
			default:
				break;
		}
		return b.build();
	}

	@Override
	public String toString() {
		return name;
	}
}

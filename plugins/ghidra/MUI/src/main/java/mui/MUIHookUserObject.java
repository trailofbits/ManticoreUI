package mui;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import ghidra.program.model.address.Address;
import manticore_server.ManticoreServerOuterClass.Hook;
import manticore_server.ManticoreServerOuterClass.Hook.HookType;
import manticore_server.ManticoreServerOuterClass.Hook.Builder;

/** 
 * User Object class used to store and conveniently display Hook information in the Hook List component 
 */
public class MUIHookUserObject {
	public HookType type;
	public String name;
	public Address address;
	public String func_text;

	/**
	 * Constructor for Find, Avoid, and Custom hooks
	 */
	public MUIHookUserObject(HookType type, Address address, String func_text) {
		this.type = type;
		this.name = address.toString();
		this.address = address;
		this.func_text = func_text;
	}

	/**
	 * Constructor for Global hooks which aren't tied to an address
	 */
	public MUIHookUserObject(HookType type, String func_text) {
		this.type = type;
		this.name = "Global " + ZonedDateTime.now(ZoneId.systemDefault())
				.format(DateTimeFormatter.ofPattern("HH:mm:ss"));
		this.func_text = func_text;
	}

	/**
	 * Builds the Hook object used in RPC calls.
	 */
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

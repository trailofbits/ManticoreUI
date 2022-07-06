package mui;

import java.nio.file.Files;
import java.util.*;
import java.util.stream.Collectors;

import com.google.gson.Gson;

import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * Outlines the key manticore arguments to display for the user, as well as
 * their sensible defaults. Settings loaded from common mui resources files.
 */
public class MUISettings {

	/**
	 * Map containing key Manticore arguments and their details including input
	 * types, defaults, and descriptions.
	 */
	public static Map<String, List<Map<String, Object>>> NATIVE_RUN_SETTINGS =
		parseRunSettings(loadResource("native_run_settings.json"));

	/**
	 * Master function that loads in a JSON common resource and deserializes it with Gson
	 * @param resourceName Filename of the resource to be loaded, which should be in the appropriate directory in MUI/os
	 * @return A Map of the deserialized JSON data, which should be put through a custom parser/typecaster for desired data to be usable.
	 */
	public static Map loadResource(String resourceName) {
		try {
			Gson gson = new Gson();
			String txt = Files.readString(Application.getOSFile(resourceName).toPath());
			Map res = gson.fromJson(txt, Map.class);
			return res;
		}
		catch (Exception e) {
			Msg.error(MUISettings.class, e.getMessage());
		}
		return new TreeMap();
	}

	/**
	 * Gson object parser for the native_run_settings.json file.
	 * @param res Deserialized JSON object.
	 * @return Map of key Manticore arguments and their details 
	 */
	private static Map<String, List<Map<String, Object>>> parseRunSettings(Map res) {
		Map<String, List<Map<String, Object>>> data =
			(Map<String, List<Map<String, Object>>>) res.get("data");
		List<String> exclusions = ((Map<String, List<String>>) res.get("exclusions")).get("ghidra");
		data = data.entrySet()
				.stream()
				.filter(x -> !exclusions.contains(x.getKey()))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
		return data;
	}

}

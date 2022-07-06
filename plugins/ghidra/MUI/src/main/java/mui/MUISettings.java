package mui;

import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.util.*;
import java.util.stream.Collectors;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * Outlines the key manticore arguments to display for the user, as well as
 * their sensible defaults. Should eventually be deprecated for a more
 * interoperable format.
 * 
 * @see <a href=
 *      "https://github.com/trailofbits/ManticoreUI/blob/master/mui/settings.py">Binary
 *      Ninja plugin equivalent</a>
 */
public class MUISettings {

	public static Map loadResource(String resourceName) {
		try {
			Gson gson = new Gson();
			String txt = Files.readString(Application.getOSFile(resourceName).toPath());
			Map res = gson.fromJson(txt, Map.class);
			return res;
		}
		catch (Exception e) {
			Msg.info(MUISettings.class, e.getMessage());
		}
		return new TreeMap();

	}

	/**
	 * Map containing key Manticore arguments and their details including input
	 * types, defaults, and descriptions.
	 */
	public static Map<String, List<Map<String, Object>>> NATIVE_RUN_SETTINGS =
		parseRunSettings(loadResource("native_run_settings.json"));

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

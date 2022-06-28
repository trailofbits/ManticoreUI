package mui;

import java.util.*;

/**
 * Outlines the key manticore arguments to display for the user, as well as their sensible defaults. Should eventually be deprecated for a more interoperable format.
 * @see <a href="https://github.com/trailofbits/ManticoreUI/blob/master/mui/settings.py">Binary Ninja plugin equivalent</a>
 */
public class MUISettings {

	/**
	 * Map containing key Manticore arguments and their details including input types, defaults, and descriptions.
	 */
	//
	public static Map<String, TreeMap<String, Map<String, Object>[]>> SETTINGS =
		Map.of(
			"NATIVE_RUN_SETTINGS",
			new TreeMap(Map.of(
				"data", new Map[] {
					Map.of(
						"title", "Concrete Start",
						"description", "Initial concrete data for the input symbolic buffer",
						"type", "string",
						"default", ""),
					Map.of() },
				"native.stdin_size", new Map[] {
					Map.of(
						"title", "Stdin Size",
						"description", "Stdin size to use for manticore",
						"type", "number",
						"default", 256),
					Map.of() },
				"argv", new Map[] {
					Map.of(
						"title", "Program arguments (use + as a wildcard)",
						"description", "Argv to use for manticore",
						"type", "array",
						"elementType", "string",
						"default", ""),
					Map.of() },
				"env", new Map[] {
					Map.of(
						"title", "Environment Variables",
						"description", "Environment variables for manticore",
						"type", "array",
						"elementType", "string",
						"default", ""),
					Map.of() },
				"file", new Map[] {
					Map.of(
						"title", "Symbolic Input Files",
						"description", "Symbolic input files for manticore",
						"type", "array",
						"elementType", "string",
						"default", ""),
					Map.of() })));

}

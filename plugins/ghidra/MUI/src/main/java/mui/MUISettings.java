package mui;

import java.util.ArrayList;
import java.util.Map;

public class MUISettings {

	public static Map<String, Map<String, Map<String, Object>[]>> SETTINGS =
		Map.of(
			"NATIVE_RUN_SETTINGS",
			Map.of(
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
				"workspace", new Map[] {
					Map.of(
						"title", "Workspace URL",
						"description", "Workspace URL to use for manticore",
						"type", "string",
						"default", "mem:"),
					Map.of(
						"is_dir_path", true) },
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
					Map.of() }));

}

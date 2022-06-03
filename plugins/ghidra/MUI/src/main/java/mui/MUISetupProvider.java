package mui;

import docking.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import muicore.MUICore.Hook;
import muicore.MUICore.NativeArguments;
import muicore.MUICore.Hook.HookType;

import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ArrayList;
import javax.swing.*;

/**
 * Provides the "MUI Setup" component used to set the arguments for and run Manticore.
 */
public class MUISetupProvider extends ComponentProviderAdapter {

	private Program program;

	private JPanel mainPanel;
	private String programPath;
	private JPanel formPanel;

	public MUIHookListComponent setupHookList;

	private HashMap<String, JTextField> formOptions;

	public MUISetupProvider(PluginTool tool, String name) {
		super(tool, name, name);
		buildFormPanel();
		buildMainPanel();
		setTitle("MUI Setup");
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setVisible(false);
	}

	/**
	 * Builds the component where key manticore arguments are displayed with dedicated input fields which are loaded with sensible defaults. Arguments include are defined in MUISettings.
	 * @see MUISettings#SETTINGS
	 * @throws UnsupportedOperationException
	 */
	private void buildFormPanel() throws UnsupportedOperationException {
		formPanel = new JPanel();
		formPanel.setLayout(
			new GridLayout(MUISettings.SETTINGS.get("NATIVE_RUN_SETTINGS").size(), 2));
		formPanel.setMinimumSize(new Dimension(800, 500));

		formOptions = new HashMap<String, JTextField>();

		for (Entry<String, Map<String, Object>[]> option : MUISettings.SETTINGS
				.get("NATIVE_RUN_SETTINGS")
				.entrySet()) {
			String name = option.getKey();

			Map<String, Object> prop = option.getValue()[0];
			Map<String, Object> extra = option.getValue()[1];

			String title = (String) prop.get("title");
			formPanel.add(new JLabel(title));

			if (extra.containsKey("is_dir_path") && (Boolean) extra.get("is_dir_path")) {
				formOptions.put(name,
					createPathInput(prop.get("default").toString()));
			}
			else if (prop.get("type") == "string" || prop.get("type") == "number") {
				formOptions.put(name, createStringNumberInput(prop.get("default").toString()));
			}
			else if (prop.get("type") == "array") {
				formOptions.put(name, createArrayInput());
			}
			else {
				// TODO: to achieve parity with Binja MUI, type==boolean must be supported, but not needed as part of sensible defaults for running manticore on native binaries
				throw new UnsupportedOperationException(
					String.format("[ERROR] Cannot create input row for %s with the type %s", name,
						prop.get("type")));
			}
		}
	}

	/** 
	 * Creates JTextField for a string/number Manticore argument and adds it to the Setup Panel.
	 * @param defaultStr The default value of the string/number argument, which should be set in MUISettings.
	 * @return An editable JTextField through which a user can set a string/number argument.
	 */
	private JTextField createStringNumberInput(String defaultStr) {
		JTextField entry = new JTextField();
		entry.setText(defaultStr);
		entry.setToolTipText("Only 1 value allowed");
		formPanel.add(entry);
		return entry;
	}

	/** 
	 * Creates JTextField for an array Manticore argument and adds it to the Setup Panel. The user is expected to space-separate each element in the array. Tokenizer supports escaped spaces or spaces within quotes.
	 * @implNote Should mimic Binary Ninja plugin behavior in future, which would allow for removal of tokenizer.
	 * @see MUILogProvider#tokenizeArrayInput
	 * @return An editable JTextField through which a user can set an array argument.
	 */
	private JTextField createArrayInput() {
		// TODO: doesn't handle default param for arrays, but not needed as part of sensible defaults for running manticore on native binaries
		// for now, same UI as string/num, and we will parse space-separated args
		JTextField entry = new JTextField();
		entry.setToolTipText("You can space-separate multiple arguments");
		formPanel.add(entry);
		return entry;
	}

	/** 
	 * Creates JTextField and file selector dialog (shown by a select button) for a path Manticore argument and adds it to the Setup Panel.
	 * @param defaultStr The default value of the path argument.
	 * @return An editable JTextField through which a user can set a path argument.
	 */
	private JTextField createPathInput(String defaultStr) {
		JTextField entry = new JTextField();

		JPanel inputRow = new JPanel(new GridBagLayout());
		GridBagConstraints constraints = new GridBagConstraints();
		constraints.fill = GridBagConstraints.HORIZONTAL;
		//inputRow.setMinimumSize(new Dimension(800, 100));

		entry.setText(defaultStr);
		entry.setPreferredSize(new Dimension(160, 27));
		constraints.gridx = 0;
		constraints.gridwidth = 2;
		constraints.gridy = 0;
		constraints.weightx = 0.66;
		inputRow.add(entry, constraints);

		JFileChooser chooser = new JFileChooser();
		chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		chooser.setDialogTitle("Set Workspace Folder");

		JButton selectButton = new JButton("Select...");
		selectButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				int returnVal = chooser.showOpenDialog(null);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					try {
						String path = chooser.getSelectedFile().getCanonicalPath();
						entry.setText(path);
					}
					catch (IOException e1) {
						e1.printStackTrace();
					}
				}
			}

		});
		constraints.gridx = 2;
		constraints.gridwidth = 1;
		constraints.weightx = 0.33;
		inputRow.add(selectButton, constraints);

		formPanel.add(inputRow);
		return entry;
	}

	/**
	 * Builds the main component panel which wraps formPanel and includes a JTextArea where user can specify additional args, the Run button, and displays warnings for when user interacts with unsupported Find/Avoid feature.
	 */
	private void buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.setMinimumSize(new Dimension(900, 800));

		mainPanel.add(formPanel, BorderLayout.CENTER);

		JPanel bottomPanel = new JPanel(new BorderLayout());

		JPanel moreArgsPanel = new JPanel(new BorderLayout());

		moreArgsPanel.add(new JLabel("Extra Manticore Arguments:"), BorderLayout.NORTH);

		JTextArea moreArgs = new JTextArea();
		moreArgs.setLineWrap(true);
		moreArgs.setWrapStyleWord(true);
		moreArgsPanel.add(moreArgs, BorderLayout.CENTER);

		setupHookList = new MUIHookListComponent();
		setupHookList.setSize(new Dimension(900, 100));
		setupHookList.setMaximumSize(new Dimension(900, 300));
		moreArgsPanel.add(setupHookList, BorderLayout.SOUTH);

		bottomPanel.add(moreArgsPanel, BorderLayout.CENTER);

		JButton runBtn = new JButton("Run");
		runBtn.addActionListener(
			new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {

					NativeArguments mcoreArgs = NativeArguments.newBuilder()
							.setProgramPath(programPath)
							.addAllBinaryArgs(tokenizeArrayInput(formOptions.get("argv").getText()))
							.addAllEnvp(tokenizeArrayInput(formOptions.get("env").getText()))
							.addAllSymbolicFiles(
								tokenizeArrayInput(formOptions.get("file").getText()))
							.setStdinSize(formOptions.get("native.stdin_size").getText())
							.setConcreteStart(formOptions.get("data").getText())
							.setAdditionalMcoreArgs(moreArgs.getText())
							.addAllHooks(setupHookList.getAllMUIHooks())
							.build();

					ManticoreRunner runner = new ManticoreRunner();
					runner.startManticore(mcoreArgs);

					MUIPlugin.log.setVisible(true);
					MUIPlugin.stateList.setVisible(true);
					MUIPlugin.log.addLogTab(runner);

					setupHookList.clearHooks();
				}
			});
		bottomPanel.add(runBtn, BorderLayout.SOUTH);

		mainPanel.add(bottomPanel, BorderLayout.SOUTH);
	}

	/**
	 * Tokenizes a String containing multiple arguments formatted shell-style, cognizant of spaces which are escaped or within quotes.
	 * @param string Shell-style space-separated arguments for Manticore arguments with array input type.
	 * @return String iterable suitable to be passed to a ProcessBuilder.
	 */
	private List<String> tokenizeArrayInput(String string) {
		final List<Character> WORD_DELIMITERS = Arrays.asList(' ', '\t');
		final List<Character> QUOTE_CHARACTERS = Arrays.asList('"', '\'');
		final char ESCAPE_CHARACTER = '\\';

		StringBuilder wordBuilder = new StringBuilder();
		List<String> words = new ArrayList<>();
		char quote = 0;

		for (int i = 0; i < string.length(); i++) {
			char c = string.charAt(i);

			if (c == ESCAPE_CHARACTER && i + 1 < string.length()) {
				wordBuilder.append(string.charAt(++i));
			}
			else if (WORD_DELIMITERS.contains(c) && quote == 0) {
				words.add(wordBuilder.toString());
				wordBuilder.setLength(0);
			}
			else if (quote == 0 && QUOTE_CHARACTERS.contains(c)) {
				quote = c;
			}
			else if (quote == c) {
				quote = 0;
			}
			else {
				wordBuilder.append(c);
			}
		}

		if (wordBuilder.length() > 0) {
			words.add(wordBuilder.toString());
		}

		return words;
	}

	/** 
	 * Called once the binary being analyzed in Ghidra has been activated.
	 * @param p the binary being analyzed in Ghidra
	 * @see MUIPlugin#programActivated(Program)
	 */
	public void setProgram(Program p) {
		program = p;
		programPath = program.getExecutablePath();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

}

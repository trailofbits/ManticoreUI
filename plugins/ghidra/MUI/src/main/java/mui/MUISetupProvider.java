package mui;

import docking.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.*;

/**
 * Provides the "MUI Setup" component used to set the arguments for and run Manticore.
 */
public class MUISetupProvider extends ComponentProviderAdapter {

	private Program program;

	private JPanel mainPanel;
	private String programPath;
	private String bundledManticorePath;

	private MUILogProvider logProvider;
	private MUIStateListProvider stateListProvider;

	private JPanel formPanel;
	public static JLabel findAvoidUnimplementedLbl;

	private HashMap<String, JTextField> formOptions;

	public MUISetupProvider(PluginTool tool, String name, MUILogProvider log,
			MUIStateListProvider stateList) {
		super(tool, name, name);
		setLogProvider(log);
		setStateListProvider(stateList);
		buildFormPanel();
		buildMainPanel();
		setTitle("MUI Setup");
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setVisible(false);
	}

	private void setLogProvider(MUILogProvider log) {
		logProvider = log;
	}

	private void setStateListProvider(MUIStateListProvider stateList) {
		stateListProvider = stateList;
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

		try {
			if (!Application.isInitialized()) {
				Application.initializeApplication(
					new GhidraApplicationLayout(), new ApplicationConfiguration());
			}
			bundledManticorePath = Application.getOSFile("manticore").getCanonicalPath();
		}
		catch (Exception e) {
			bundledManticorePath = "";
		}

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
					createPathInput((name == "{mcore_binary}" ? bundledManticorePath
							: prop.get("default").toString())));
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
		mainPanel.setMinimumSize(new Dimension(900, 500));

		mainPanel.add(formPanel, BorderLayout.CENTER);

		JPanel bottomPanel = new JPanel(new BorderLayout());

		findAvoidUnimplementedLbl = new JLabel(
			"<html>WARNING: You have set instructions for Manticore to Find/Avoid in the Listing window. Find/Avoid functionality has NOT been implemented for MUI-Ghidra, and clicking 'Run' will result in Manticore exploring all paths as per usual.</html>");
		findAvoidUnimplementedLbl.setForeground(new Color(139, 0, 0)); // DARK RED
		findAvoidUnimplementedLbl.setHorizontalAlignment(SwingConstants.CENTER);

		bottomPanel.add(findAvoidUnimplementedLbl, BorderLayout.CENTER);
		findAvoidUnimplementedLbl.setVisible(false);

		JPanel moreArgsPanel = new JPanel(new BorderLayout());

		moreArgsPanel.add(new JLabel("Extra Manticore Arguments:"), BorderLayout.NORTH);

		JTextArea moreArgs = new JTextArea();
		moreArgs.setLineWrap(true);
		moreArgs.setWrapStyleWord(true);
		moreArgsPanel.add(moreArgs, BorderLayout.CENTER);

		bottomPanel.add(moreArgsPanel, BorderLayout.NORTH);

		JButton runBtn = new JButton("Run");
		runBtn.addActionListener(
			new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					logProvider.setVisible(true);
					stateListProvider.setVisible(true);
					logProvider.runMUI(programPath, formOptions, moreArgs.getText());
				}
			});
		bottomPanel.add(runBtn, BorderLayout.SOUTH);

		mainPanel.add(bottomPanel, BorderLayout.SOUTH);
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

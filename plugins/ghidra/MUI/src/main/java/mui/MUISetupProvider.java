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

public class MUISetupProvider extends ComponentProviderAdapter {

	private Program program;

	private JPanel mainPanel;
	private String programPath;
	private String manticoreExePath;

	private MUILogProvider logProvider;

	private JPanel formPanel;

	private HashMap<String, JTextField> formOptions;

	public MUISetupProvider(PluginTool tool, String name, MUILogProvider log) {
		super(tool, name, name);
		setLogProvider(log);
		buildFormPanel();
		buildMainPanel();
		setTitle("MUI Setup");
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setVisible(true);
	}

	private void setLogProvider(MUILogProvider log) {
		logProvider = log;
	}

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
				formOptions.put(name, createPathInput(prop.get("default").toString()));
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

	private JTextField createStringNumberInput(String defaultStr) {
		JTextField entry = new JTextField();
		entry.setText(defaultStr);
		entry.setToolTipText("Only 1 value allowed");
		formPanel.add(entry);
		return entry;
	}

	private JTextField createArrayInput() {
		// TODO: doesn't handle default param for arrays, but not needed as part of sensible defaults for running manticore on native binaries
		// for now, same UI as string/num, and we will parse space-separated args
		JTextField entry = new JTextField();
		entry.setToolTipText("You can space-separate multiple arguments");
		formPanel.add(entry);
		return entry;
	}

	private JTextField createPathInput(String defaultStr) {
		JTextField entry = new JTextField();

		JPanel inputRow = new JPanel(new GridBagLayout());
		inputRow.setMinimumSize(new Dimension(800, 100));
		GridBagConstraints inputRowConstraints = new GridBagConstraints();
		inputRowConstraints.fill = GridBagConstraints.HORIZONTAL;

		inputRowConstraints.gridx = 0;
		inputRowConstraints.gridwidth = 3;
		inputRowConstraints.gridy = 0;
		inputRowConstraints.gridheight = 1;
		inputRowConstraints.weightx = 0.75;

		entry.setText(defaultStr);
		inputRow.add(entry, inputRowConstraints);

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

		inputRowConstraints.gridx = 3;
		inputRowConstraints.gridwidth = 1;
		inputRowConstraints.weightx = 0.25;
		inputRow.add(selectButton, inputRowConstraints);

		formPanel.add(inputRow);
		return entry;
	}

	private void buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.setMinimumSize(new Dimension(900, 500));

		mainPanel.add(formPanel, BorderLayout.CENTER);

		try {
			if (!Application.isInitialized()) {
				Application.initializeApplication(
					new GhidraApplicationLayout(), new ApplicationConfiguration());
			}
			manticoreExePath = Application.getOSFile("manticore").getCanonicalPath();
		}
		catch (Exception e) {
			manticoreExePath = "";
		}

		JPanel bottomPanel = new JPanel(new BorderLayout());

		bottomPanel.add(new JLabel("Extra Manticore Arguments:"), BorderLayout.NORTH);

		JTextArea moreArgs = new JTextArea();
		moreArgs.setLineWrap(true);
		moreArgs.setWrapStyleWord(true);
		bottomPanel.add(moreArgs, BorderLayout.CENTER);

		JButton runBtn = new JButton("Run");
		runBtn.addActionListener(
			new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					if (manticoreExePath.length() == 0) {
						logProvider.noManticoreBinary();
					}
					else {
						logProvider.runMUI(
							manticoreExePath, programPath, formOptions, moreArgs.getText());
					}
				}
			});
		bottomPanel.add(runBtn, BorderLayout.SOUTH);

		mainPanel.add(bottomPanel, BorderLayout.SOUTH);
	}

	public void setProgram(Program p) {
		program = p;
		programPath = program.getExecutablePath();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}
}

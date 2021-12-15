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
import java.util.*;
import java.util.List;
import javax.swing.*;

public class MUISetupProvider extends ComponentProviderAdapter {

	private Program program;

	private JPanel mainPanel;
	private GridBagConstraints mainPanelConstraints;

	private JPanel inputPanel;
	private GridBagConstraints inputPanelConstraints;
	private JTextArea manticoreArgsArea;
	private JLabel programPathLbl;
	private String programPath;
	private JButton runBtn;
	private String manticoreExePath;

	private MUILogProvider logProvider;

	public MUISetupProvider(PluginTool tool, String name, MUILogProvider log) {
		super(tool, name, name);
		setLogProvider(log);
		buildMainPanel();
		setTitle("MUI Setup");
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setVisible(true);
	}

	private void setLogProvider(MUILogProvider log) {
		logProvider = log;
	}

	private void buildMainPanel() {
		mainPanel = new JPanel(new GridBagLayout());
		mainPanel.setMinimumSize(new Dimension(500, 500));

		mainPanelConstraints = new GridBagConstraints();
		mainPanelConstraints.fill = GridBagConstraints.BOTH;
		mainPanelConstraints.gridwidth = GridBagConstraints.REMAINDER;
		mainPanelConstraints.weightx = 0.9;
		mainPanelConstraints.weighty = 0.9;

		inputPanel = new JPanel(new GridBagLayout());

		inputPanelConstraints = new GridBagConstraints();
		inputPanelConstraints.fill = GridBagConstraints.BOTH;

		inputPanelConstraints.gridx = 0;
		inputPanelConstraints.gridy = 0;
		inputPanelConstraints.weightx = 0.25;
		inputPanelConstraints.gridwidth = 1;
		inputPanel.add(new JLabel("Program Path:"), inputPanelConstraints);

		if (programPath == null) {
			programPath = "";
		}
		programPathLbl = new JLabel(programPath);
		inputPanelConstraints.gridx = 1;
		inputPanelConstraints.gridy = 0;
		inputPanelConstraints.weightx = 0.75;
		inputPanelConstraints.gridwidth = 3;
		inputPanel.add(programPathLbl, inputPanelConstraints);

		JLabel manticoreArgsLbl = new JLabel("Manticore Args:");
		inputPanelConstraints.gridx = 0;
		inputPanelConstraints.gridy = 1;
		inputPanelConstraints.weightx = 0.0;
		inputPanelConstraints.gridwidth = 4;
		inputPanel.add(manticoreArgsLbl, inputPanelConstraints);

		manticoreArgsArea = new JTextArea();
		manticoreArgsArea.setToolTipText("Enter arguments as you would in CLI");
		manticoreArgsArea.setLineWrap(true);
		manticoreArgsArea.setWrapStyleWord(true);
		inputPanelConstraints.gridx = 0;
		inputPanelConstraints.gridy = 2;
		inputPanelConstraints.ipady = 50;
		inputPanelConstraints.weightx = 0.0;
		inputPanelConstraints.gridwidth = 4;
		inputPanel.add(manticoreArgsArea, inputPanelConstraints);

		try {
			if (!Application.isInitialized()) {
				Application.initializeApplication(
					new GhidraApplicationLayout(), new ApplicationConfiguration());
			}
			manticoreExePath = Application.getOSFile("manticore").getAbsolutePath().concat(" ");
		}
		catch (Exception e) {
			manticoreExePath = "";
		}
		runBtn = new JButton("Run");
		runBtn.addActionListener(
			new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					if (manticoreExePath.length() == 0) {
						logProvider.noManticoreBinary();
					}
					else {
						logProvider.runMUI(
							parseCommand(manticoreExePath.concat(manticoreArgsArea.getText())));
					}
				}
			});
		inputPanelConstraints.gridx = 0;
		inputPanelConstraints.gridy = 3;
		inputPanelConstraints.weightx = 0.9;
		inputPanelConstraints.anchor = GridBagConstraints.SOUTH;
		inputPanelConstraints.ipady = 0;
		inputPanelConstraints.gridwidth = 4;
		inputPanelConstraints.insets = new Insets(10, 0, 0, 0);
		inputPanel.add(runBtn, inputPanelConstraints);

		mainPanel.add(inputPanel, mainPanelConstraints);
	}

	public void setProgram(Program p) {
		program = p;
		programPath = program.getExecutablePath();
		if (programPathLbl != null) { // if mainPanel built before program activated
			programPathLbl.setText(programPath);
		}
		manticoreArgsArea.setText("--workspace tmpMUI ".concat(programPath));
	}

	/**
	 * Tokenizes a string by spaces, but takes into account spaces embedded in quotes or escaped
	 * spaces. Should no longer be required once UI for args is implemented.
	 */
	public String[] parseCommand(String string) {
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

		return words.toArray(new String[0]);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}
}

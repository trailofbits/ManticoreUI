package mui;

import java.awt.*;
import java.awt.event.*;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JToolBar;
import javax.swing.ScrollPaneConstants;
import resources.ResourceManager;

public class MUILogContentComponent extends JPanel {

	public MUIRunner MUIInstance;

	public JTextArea logArea;
	public JButton stopButton;

	public MUILogContentComponent() {
		setLayout(new BorderLayout());
		setMinimumSize(new Dimension(300, 300));

		logArea = new JTextArea();
		stopButton = new JButton();

		buildLogArea();
		MUIInstance = new MUIRunner(logArea, stopButton);
		buildToolBar();
	}

	public void buildLogArea() {
		logArea.setEditable(false);
		logArea.setLineWrap(true);
		logArea.setWrapStyleWord(true);
		JScrollPane logScrollPane =
			new JScrollPane(
				logArea,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

		add(logScrollPane, BorderLayout.CENTER);
	}

	public void buildToolBar() {
		JToolBar logToolBar = new JToolBar();
		logToolBar.setFloatable(false);
		stopButton.setIcon(ResourceManager.loadImage("images/stopNode.png"));
		stopButton.addActionListener(
			new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					MUIInstance.stopProc();
				}
			});
		logToolBar.add(Box.createGlue()); // shifts buttons to the right
		logToolBar.add(stopButton);

		add(logToolBar, BorderLayout.PAGE_START);
	}
}

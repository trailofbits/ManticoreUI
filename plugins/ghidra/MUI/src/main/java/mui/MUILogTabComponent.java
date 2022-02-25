package mui;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.plaf.basic.BasicButtonUI;

/**
 * Provides the component for the Tab itself in the MUI Log tabbed pane, including behaviour when switching and closing tabs.
 */
public class MUILogTabComponent extends JPanel {
	private JTabbedPane parentPane;
	private MUILogProvider logProvider;

	public MUILogTabComponent(JTabbedPane parentPane, MUILogProvider logProvider) {
		super(new FlowLayout(FlowLayout.LEFT, 0, 0));
		if (parentPane == null) {
			throw new NullPointerException("no parent pane!");
		}
		this.parentPane = parentPane;
		this.logProvider = logProvider;
		setOpaque(false);

		JLabel titleLbl =
			new JLabel() {
				public String getText() {
					int i = parentPane.indexOfTabComponent(MUILogTabComponent.this);
					if (i != -1) {
						return parentPane.getTitleAt(i);
					}
					return null;
				}
			};

		add(titleLbl);
		titleLbl.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5));
		titleLbl.addMouseListener(switchTabMouseAdapter);
		JButton button = new LogTabCloseButton();
		add(button);
		setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0));
		addMouseListener(switchTabMouseAdapter);
	}

	private class LogTabCloseButton extends JButton implements ActionListener {
		public LogTabCloseButton() {
			int size = 17;
			setPreferredSize(new Dimension(size, size));
			setToolTipText("close this tab");
			setUI(new BasicButtonUI());
			setContentAreaFilled(false);
			setFocusable(false);
			setBorder(BorderFactory.createEtchedBorder());
			setBorderPainted(false);
			addMouseListener(closeButtonMouseListener);
			setRolloverEnabled(true);
			addActionListener(this);
		}

		/**
		 * Closes tab when close button is clicked, and calls additional method to handle auxiliary functions.
		 * @see MUILogProvider#closeLogTab(int)
		 */
		public void actionPerformed(ActionEvent e) {
			int i = parentPane.indexOfTabComponent(MUILogTabComponent.this);
			if (i != -1) {
				logProvider.closeLogTab(i);
			}
		}

		/**
		 * Overrides the updateUI method with no action, since the Tab and thus the Button will be closed on click anyways.
		 */
		@Override
		public void updateUI() {
		}

		/**
		 * Natively paints the close button graphic.
		 */
		protected void paintComponent(Graphics g) {
			super.paintComponent(g);
			Graphics2D g2 = (Graphics2D) g.create();
			if (getModel().isPressed()) {
				g2.translate(1, 1);
			}
			g2.setStroke(new BasicStroke(2));
			g2.setColor(Color.BLACK);
			if (getModel().isRollover()) {
				g2.setColor(Color.MAGENTA);
			}
			int delta = 6;
			g2.drawLine(delta, delta, getWidth() - delta - 1, getHeight() - delta - 1);
			g2.drawLine(getWidth() - delta - 1, delta, delta, getHeight() - delta - 1);
			g2.dispose();
		}
	}

	/**
	 * Handles tab switching, including auxiliary behavior such as reflecting the State List of the newly-focused Manticore instance.
	 */
	private final MouseAdapter switchTabMouseAdapter =
		new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				int index = parentPane.indexOfTabComponent(MUILogTabComponent.this);
				parentPane.setSelectedIndex(index);
				MUILogContentComponent tabContent =
					(MUILogContentComponent) parentPane.getComponentAt(index);
				MUIStateListProvider.changeRunner(tabContent.manticoreRunner);
			}
		};

	/**
	 * Handles UI changes when mousing over and clicking into the close tab button.
	 */
	private final MouseListener closeButtonMouseListener =
		new MouseAdapter() {
			public void mouseEntered(MouseEvent e) {
				Component component = e.getComponent();
				if (component instanceof AbstractButton) {
					AbstractButton button = (AbstractButton) component;
					button.setBorderPainted(true);
				}
			}

			public void mouseExited(MouseEvent e) {
				Component component = e.getComponent();
				if (component instanceof AbstractButton) {
					AbstractButton button = (AbstractButton) component;
					button.setBorderPainted(false);
				}
			}
		};
}

#include "MainWindow.hpp"

#include <QApplication>
#include <QIcon>
#include <QPalette>
#include <QStyleFactory>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("CryptEX Qt"));
    app.setOrganizationName(QStringLiteral("CryptEX"));
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    app.setWindowIcon(QIcon(QStringLiteral(":/branding/CryptEXlogo.jpeg")));

    QPalette palette;
    palette.setColor(QPalette::Window, QColor(53, 53, 53));
    palette.setColor(QPalette::WindowText, QColor(232, 232, 232));
    palette.setColor(QPalette::Base, QColor(41, 41, 41));
    palette.setColor(QPalette::AlternateBase, QColor(47, 47, 47));
    palette.setColor(QPalette::Text, QColor(230, 230, 230));
    palette.setColor(QPalette::Button, QColor(58, 58, 58));
    palette.setColor(QPalette::ButtonText, QColor(235, 235, 235));
    palette.setColor(QPalette::Highlight, QColor(84, 132, 197));
    palette.setColor(QPalette::HighlightedText, QColor(255, 255, 255));
    app.setPalette(palette);
    app.setStyleSheet(
        "QMainWindow { background: #2f2f2f; color: #eaeaea; }"
        "QWidget { color: #eaeaea; font-size: 12px; }"
        "QGroupBox { border: 1px solid #232323; border-radius: 4px; margin-top: 14px; padding-top: 14px; background: #373737; font-weight: 600; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #f2f2f2; }"
        "QPushButton { background: #4a4a4a; color: #f4f4f4; border: 1px solid #212121; border-radius: 4px; padding: 5px 12px; }"
        "QPushButton:hover { background: #575757; }"
        "QPushButton:pressed { background: #414141; }"
        "QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QTableWidget, QListWidget {"
        "  background: #343434; border: 1px solid #232323; border-radius: 3px; padding: 5px; color: #ededed; selection-background-color: #5578a8; }"
        "QLabel#pageTitle { font-size: 16px; font-weight: 700; color: #f4f4f4; margin-bottom: 4px; }"
        "QFrame#panelFrame { background: #383838; border: 1px solid #232323; border-radius: 3px; }"
        "QLabel#panelHeader { font-size: 14px; font-weight: 700; color: #f2f2f2; }"
        "QLabel#valueLabel { font-family: Menlo, Monaco, monospace; font-size: 13px; font-weight: 700; color: #f3f3f3; }"
        "QTabWidget::pane { border: 1px solid #202020; background: #333333; top: -1px; }"
        "QTabBar::tab { background: #363636; border: 1px solid #202020; border-bottom: none; padding: 8px 12px; min-width: 88px; color: #f1f1f1; }"
        "QTabBar::tab:selected { background: #404040; }"
        "QTabBar::tab:!selected { margin-top: 2px; }"
        "QWidget#startupOverlay { background: rgba(0, 0, 0, 138); }"
        "QFrame#startupPanel { background: #f4f4f4; border: 1px solid #979797; border-radius: 6px; }"
        "QLabel#startupTitle { color: #202020; font-size: 12px; font-weight: 600; }"
        "QLabel#startupBody { color: #2b2b2b; font-size: 12px; }"
        "QLabel#startupMetric { color: #222222; font-size: 12px; font-weight: 700; }"
        "QLabel#startupValue { color: #202020; font-size: 12px; }"
        "QPushButton#startupHideButton { background: #4892ff; color: #ffffff; border: 1px solid #2c72d6; padding: 4px 14px; border-radius: 4px; }"
        "QPushButton#startupHideButton:hover { background: #5aa0ff; }"
        "QStatusBar { background: #2b2b2b; color: #dddddd; border-top: 1px solid #1f1f1f; }"
    );

    MainWindow window;
    window.setWindowTitle(QStringLiteral("CryptEX Qt - Satoshi"));
    window.setWindowIcon(app.windowIcon());
    window.show();
    return app.exec();
}

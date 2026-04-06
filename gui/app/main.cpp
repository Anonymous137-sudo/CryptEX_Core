#include "MainWindow.hpp"

#include <QApplication>
#include <QDialog>
#include <QIcon>
#include <QLabel>
#include <QHBoxLayout>
#include <QPalette>
#include <QProgressBar>
#include <QTimer>
#include <QStyleFactory>
#include <QVBoxLayout>

namespace {

class StartupSplash final : public QDialog {
public:
    explicit StartupSplash(const QIcon& icon, QWidget* parent = nullptr)
        : QDialog(parent) {
        setWindowFlags(Qt::Dialog | Qt::CustomizeWindowHint | Qt::WindowTitleHint);
        setModal(false);
        setFixedSize(360, 170);
        setWindowTitle(QStringLiteral("CryptEX Core"));

        auto* root = new QHBoxLayout(this);
        root->setContentsMargins(0, 0, 0, 0);
        root->setSpacing(0);

        auto* logoPanel = new QWidget(this);
        logoPanel->setFixedWidth(150);
        logoPanel->setStyleSheet(QStringLiteral("background:#10161c;"));
        auto* logoLayout = new QVBoxLayout(logoPanel);
        auto* logoLabel = new QLabel(logoPanel);
        logoLabel->setAlignment(Qt::AlignCenter);
        logoLabel->setPixmap(icon.pixmap(108, 108));
        logoLabel->setMinimumSize(108, 108);
        logoLayout->addStretch(1);
        logoLayout->addWidget(logoLabel);
        logoLayout->addStretch(1);
        root->addWidget(logoPanel);

        auto* content = new QWidget(this);
        content->setStyleSheet(QStringLiteral("background:#f7f7f7;"));
        auto* contentLayout = new QVBoxLayout(content);
        contentLayout->setContentsMargins(18, 20, 18, 16);
        auto* title = new QLabel(QStringLiteral("CryptEX Core"), content);
        title->setStyleSheet(QStringLiteral("color:#4b4b4b; font-size:22px; font-weight:500;"));
        auto* version = new QLabel(QStringLiteral("Version v0.6.0"), content);
        version->setStyleSheet(QStringLiteral("color:#666666; font-size:12px;"));
        auto* copyright = new QLabel(QStringLiteral("© 2026 The CryptEX Core developers"), content);
        copyright->setStyleSheet(QStringLiteral("color:#666666; font-size:11px;"));
        statusLabel_ = new QLabel(QStringLiteral("Loading block index..."), content);
        statusLabel_->setStyleSheet(QStringLiteral("color:#555555; font-size:12px;"));
        progressBar_ = new QProgressBar(content);
        progressBar_->setRange(0, 0);
        progressBar_->setTextVisible(false);
        progressBar_->setFixedHeight(6);
        progressBar_->setStyleSheet(QStringLiteral(
            "QProgressBar { border:none; background:#dedede; border-radius:3px; }"
            "QProgressBar::chunk { background:#3b82f6; border-radius:3px; }"));
        contentLayout->addWidget(title);
        contentLayout->addWidget(version);
        contentLayout->addWidget(copyright);
        contentLayout->addStretch(1);
        contentLayout->addWidget(statusLabel_);
        contentLayout->addWidget(progressBar_);
        root->addWidget(content, 1);

        setWindowIcon(icon);
    }

private:
    QLabel* statusLabel_{nullptr};
    QProgressBar* progressBar_{nullptr};
};

}

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
        "QMainWindow { background: #3a3a3a; color: #eaeaea; }"
        "QWidget { color: #eaeaea; font-size: 12px; }"
        "QMenuBar { background:#2b2b2b; color:#f0f0f0; }"
        "QMenuBar::item { background:transparent; padding:4px 8px; }"
        "QMenuBar::item:selected { background:#404040; }"
        "QMenu { background:#2f2f2f; color:#f0f0f0; border:1px solid #1d1d1d; }"
        "QMenu::item:selected { background:#454545; }"
        "QGroupBox { border: 1px solid #232323; border-radius: 3px; margin-top: 12px; padding-top: 12px; background: #373737; font-weight: 600; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #f2f2f2; }"
        "QPushButton { background: #4a4a4a; color: #f4f4f4; border: 1px solid #212121; border-radius: 3px; padding: 5px 12px; }"
        "QPushButton:hover { background: #575757; }"
        "QPushButton:pressed { background: #414141; }"
        "QToolButton { background: transparent; color:#efefef; border: 1px solid transparent; border-radius: 3px; padding: 3px; }"
        "QToolButton:hover { background:#444444; border-color:#2c2c2c; }"
        "QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QTableWidget, QListWidget {"
        "  background: #343434; border: 1px solid #232323; border-radius: 3px; padding: 5px; color: #ededed; selection-background-color: #5578a8; }"
        "QLabel#pageTitle { font-size: 16px; font-weight: 700; color: #f4f4f4; margin-bottom: 4px; }"
        "QFrame#panelFrame { background: #383838; border: 1px solid #232323; border-radius: 3px; }"
        "QLabel#panelHeader { font-size: 14px; font-weight: 700; color: #f2f2f2; }"
        "QLabel#valueLabel { font-family: Menlo, Monaco, monospace; font-size: 13px; font-weight: 700; color: #f3f3f3; }"
        "QTabWidget::pane { border: 1px solid #202020; background: #333333; top: -1px; }"
        "QTabBar::tab { background: #363636; border: 1px solid #202020; border-bottom: none; padding: 7px 12px; min-width: 80px; color: #f1f1f1; }"
        "QTabBar::tab:selected { background: #404040; }"
        "QTabBar::tab:!selected { margin-top: 2px; }"
        "QWidget#startupOverlay { background: rgba(0, 0, 0, 138); }"
        "QFrame#startupPanel { background: #f4f4f4; border: 1px solid #979797; border-radius: 6px; }"
        "QLabel#startupTitle { color: #202020; font-size: 12px; font-weight: 600; }"
        "QLabel#startupBody { color: #2b2b2b; font-size: 12px; }"
        "QLabel#startupMetric { color: #222222; font-size: 12px; font-weight: 700; }"
        "QLabel#startupValue { color: #202020; font-size: 12px; }"
        "QProgressBar { border: 1px solid #4a4a4a; background: #2b2b2b; border-radius: 3px; color: #f1f1f1; }"
        "QProgressBar::chunk { background: #2f86ff; border-radius: 2px; }"
        "QProgressBar#startupProgressBar { border: 1px solid #9aa8be; background: #dfe5ef; border-radius: 4px; min-height: 12px; padding: 1px; color:#ffffff; font-weight:600; text-align:center; }"
        "QProgressBar#startupProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #7ab6ff, stop:0.45 #2f86ff, stop:1 #1663d6); border-radius: 3px; margin: 0px; }"
        "QProgressBar#syncStatusProgressBar { border: 1px solid #274e8a; background: #181f2b; border-radius: 4px; }"
        "QProgressBar#syncStatusProgressBar::chunk { background: #2f86ff; border-radius: 3px; }"
        "QPushButton#startupHideButton { background: #4892ff; color: #ffffff; border: 1px solid #2c72d6; padding: 4px 14px; border-radius: 4px; }"
        "QPushButton#startupHideButton:hover { background: #5aa0ff; }"
        "QToolButton#statusIconButton { background:transparent; border:1px solid transparent; border-radius:3px; padding:1px; margin:0 1px; }"
        "QToolButton#statusIconButton:hover { background:#3b3b3b; border-color:#232323; }"
        "QLabel#syncStatusBarLabel { color:#d9d9d9; font-weight:600; padding-right:6px; }"
        "QStatusBar { background: #2b2b2b; color: #dddddd; border-top: 1px solid #1f1f1f; }"
    );

    StartupSplash splash(app.windowIcon());
    splash.show();
    app.processEvents();

    MainWindow window;
    window.setWindowTitle(QStringLiteral("CryptEX Core - Satoshi"));
    window.setWindowIcon(app.windowIcon());

    QTimer::singleShot(2800, [&window, &splash]() {
        splash.close();
        window.show();
    });
    return app.exec();
}

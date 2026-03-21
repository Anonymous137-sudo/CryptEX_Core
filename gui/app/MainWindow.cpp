#include "MainWindow.hpp"
#include "views/DashboardPage.hpp"
#include "views/NetworkGraphPage.hpp"
#include "views/WalletPage.hpp"
#include "views/ChatPage.hpp"
#include "views/MiningPage.hpp"
#include "views/RpcConsolePage.hpp"
#include "views/TerminalPage.hpp"

#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QFrame>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QResizeEvent>
#include <QSettings>
#include <QStatusBar>
#include <QStyle>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRandomGenerator>
#include <QTextStream>
#include <QtEndian>
#include <algorithm>
#include <cmath>
#include <functional>
#include <memory>

namespace {

QString normalizeConfigKey(QString key) {
    key = key.trimmed().toLower();
    key.replace('.', '_');
    key.replace('-', '_');
    return key;
}

QString stripQuotedValue(QString value) {
    value = value.trimmed();
    if (value.size() >= 2) {
        const auto first = value.front();
        const auto last = value.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            return value.mid(1, value.size() - 2);
        }
    }
    return value;
}

QHash<QString, QString> loadSimpleConfig(const QString& path) {
    QHash<QString, QString> values;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return values;
    }

    QTextStream in(&file);
    while (!in.atEnd()) {
        const auto raw = in.readLine().trimmed();
        if (raw.isEmpty() || raw.startsWith('#') || raw.startsWith(';')) {
            continue;
        }
        const auto equals = raw.indexOf('=');
        if (equals < 0) {
            continue;
        }
        const auto key = normalizeConfigKey(raw.left(equals));
        const auto value = stripQuotedValue(raw.mid(equals + 1));
        if (!key.isEmpty()) {
            values.insert(key, value);
        }
    }
    return values;
}

QString loopbackRpcHostForBind(QString bind) {
    bind = bind.trimmed();
    if (bind.isEmpty() || bind == QStringLiteral("0.0.0.0") || bind == QStringLiteral("::") || bind == QStringLiteral("*")) {
        return QStringLiteral("127.0.0.1");
    }
    return bind;
}

quint64 parseStoredBlockLength(const QByteArray& raw) {
    if (raw.size() < static_cast<int>(sizeof(quint32) + sizeof(quint64))) {
        return 0;
    }
    return qFromLittleEndian<quint64>(reinterpret_cast<const uchar*>(raw.constData() + sizeof(quint32)));
}

quint64 parseBlockHeightFromFileName(const QString& name) {
    if (!name.startsWith(QStringLiteral("blk")) || !name.endsWith(QStringLiteral(".dat"))) {
        return 0;
    }
    bool ok = false;
    const auto value = name.mid(3, name.size() - 7).toULongLong(&ok);
    return ok ? value : 0;
}

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent) {
    buildUi();
    loadSettings();
    applyRpcSettings();
    setBackendState(QStringLiteral("Checking backend..."));

    connect(&daemon_, &DaemonController::stateChanged, this, [this](bool running) {
        if (backendBootstrapInProgress_ && running) {
            setBackendState(QStringLiteral("Backend process started, waiting for RPC..."));
        } else if (running) {
            setBackendState(QStringLiteral("Backend running"));
        } else {
            setBackendState(QStringLiteral("Backend stopped"));
        }
    });
    connect(&daemon_, &DaemonController::outputLine, this, [this](const QString& line) {
        systemLogView_->appendPlainText(QStringLiteral("[daemon] ") + line);
    });
    connect(&daemon_, &DaemonController::errorLine, this, [this](const QString& line) {
        systemLogView_->appendPlainText(QStringLiteral("[daemon-error] ") + line);
    });
    connect(&miner_, &MinerController::stateChanged, this, [this](bool running) {
        minerOutputView_->appendPlainText(running ? QStringLiteral("[miner] process started")
                                                  : QStringLiteral("[miner] process stopped"));
    });
    connect(&miner_, &MinerController::outputLine, this, [this](const QString& line) {
        minerOutputView_->appendPlainText(QStringLiteral("[miner] ") + line);
        if (line.startsWith(QStringLiteral("MinedBlockHex:"), Qt::CaseInsensitive)) {
            submitMinedBlockToBackend(line.section(':', 1).trimmed());
            return;
        }
        if (line.contains(QStringLiteral("Block successfully added to chain."), Qt::CaseInsensitive) ||
            line.contains(QStringLiteral("Mining session complete"), Qt::CaseInsensitive) ||
            line.contains(QStringLiteral("block accepted"), Qt::CaseInsensitive)) {
            QTimer::singleShot(1500, this, [this]() { refreshAll(); });
        }
    });
    connect(&miner_, &MinerController::errorLine, this, [this](const QString& line) {
        minerOutputView_->appendPlainText(QStringLiteral("[miner-error] ") + line);
    });
    connect(&rpc_, &RpcClient::transportError, this, [this](const QString& error) {
        if (backendBootstrapInProgress_) return;
        setConnectionStatus(error, true);
    });

    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(10000);
    connect(refreshTimer_, &QTimer::timeout, this, [this]() { refreshAll(); });
    refreshTimer_->start();

    QTimer::singleShot(0, this, [this]() { bootstrapBackendAndRefresh(); });
}

void MainWindow::buildUi() {
    setWindowTitle(QStringLiteral("CryptEX Qt - Satoshi"));
    resize(1060, 720);
    setMinimumSize(980, 660);

    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(8, 8, 8, 6);
    root->setSpacing(6);

    auto* topFrame = new QFrame(central);
    topFrame->setObjectName(QStringLiteral("panelFrame"));
    auto* topLayout = new QHBoxLayout(topFrame);
    topLayout->setContentsMargins(10, 8, 10, 8);
    topLayout->setSpacing(8);
    auto* titleLabel = new QLabel(QStringLiteral("CryptEX Qt"), topFrame);
    titleLabel->setObjectName(QStringLiteral("pageTitle"));
    daemonStatusLabel_ = new QLabel(QStringLiteral("Backend stopped"), topFrame);
    daemonStatusLabel_->setObjectName(QStringLiteral("valueLabel"));
    auto* networkHint = new QLabel(QStringLiteral("Network"), topFrame);
    networkCombo_ = new QComboBox(topFrame);
    networkCombo_->addItems({QStringLiteral("mainnet"), QStringLiteral("testnet"), QStringLiteral("regtest")});
    syncDetailsButton_ = new QPushButton(QStringLiteral("Sync Details"), topFrame);
    auto* refreshButton = new QPushButton(QStringLiteral("Refresh"), topFrame);
    topLayout->addWidget(titleLabel);
    topLayout->addStretch(1);
    topLayout->addWidget(networkHint);
    topLayout->addWidget(networkCombo_);
    topLayout->addWidget(new QLabel(QStringLiteral("Node"), topFrame));
    topLayout->addWidget(daemonStatusLabel_);
    topLayout->addWidget(syncDetailsButton_);
    topLayout->addWidget(refreshButton);
    root->addWidget(topFrame);

    tabs_ = new QTabWidget(central);
    tabs_->tabBar()->setDocumentMode(true);
    tabs_->tabBar()->setExpanding(false);
    tabs_->setIconSize(QSize(18, 18));

    dashboardPage_ = new DashboardPage(tabs_);
    networkGraphPage_ = new NetworkGraphPage(tabs_);
    walletPage_ = new WalletPage(tabs_);
    chatPage_ = new ChatPage(tabs_);
    miningPage_ = new MiningPage(tabs_);
    rpcConsolePage_ = new RpcConsolePage(tabs_);
    terminalPage_ = new TerminalPage(tabs_);
    auto* minerOutputPage = new QWidget(tabs_);
    settingsPage_ = new QWidget(tabs_);

    dashboardPage_->setRpcClient(&rpc_);
    networkGraphPage_->setRpcClient(&rpc_);
    walletPage_->setRpcClient(&rpc_);
    chatPage_->setRpcClient(&rpc_);
    miningPage_->setRpcClient(&rpc_);
    rpcConsolePage_->setRpcClient(&rpc_);
    miningPage_->setMinerController(&miner_);

    rpcUrlEdit_ = new QLineEdit(QStringLiteral("http://127.0.0.1:9332/"), settingsPage_);
    rpcUserEdit_ = new QLineEdit(QStringLiteral("admin"), settingsPage_);
    rpcPasswordEdit_ = new QLineEdit(settingsPage_);
    rpcPasswordEdit_->setEchoMode(QLineEdit::Password);
    daemonPathEdit_ = new QLineEdit(guessedDaemonPath(), settingsPage_);
    dataDirEdit_ = new QLineEdit(settingsPage_);
    walletPathEdit_ = new QLineEdit(settingsPage_);
    walletPassEdit_ = new QLineEdit(settingsPage_);
    walletPassEdit_->setEchoMode(QLineEdit::Password);

    miningPage_->setBaseLaunchConfigProvider([this]() {
        MinerController::LaunchConfig config;
        config.executablePath = daemonPathEdit_->text().trimmed();
        config.network = networkCombo_->currentText();
        config.dataDir = dataDirEdit_->text().trimmed();
        return config;
    });

    auto* settingsRoot = new QVBoxLayout(settingsPage_);
    settingsRoot->setContentsMargins(12, 12, 12, 12);
    settingsRoot->setSpacing(12);

    auto* connectionBox = new QGroupBox(QStringLiteral("Node / RPC Settings"), settingsPage_);
    auto* backendLayout = new QGridLayout(connectionBox);
    auto* connectButton = new QPushButton(QStringLiteral("Connect"), connectionBox);
    auto* saveButton = new QPushButton(QStringLiteral("Save"), connectionBox);
    auto* startButton = new QPushButton(QStringLiteral("Start Backend"), connectionBox);
    auto* stopButton = new QPushButton(QStringLiteral("Stop Backend"), connectionBox);

    backendLayout->addWidget(new QLabel(QStringLiteral("RPC URL")), 0, 0);
    backendLayout->addWidget(rpcUrlEdit_, 0, 1);
    backendLayout->addWidget(new QLabel(QStringLiteral("RPC User")), 0, 2);
    backendLayout->addWidget(rpcUserEdit_, 0, 3);
    backendLayout->addWidget(new QLabel(QStringLiteral("RPC Password")), 1, 0);
    backendLayout->addWidget(rpcPasswordEdit_, 1, 1);
    backendLayout->addWidget(new QLabel(QStringLiteral("Daemon Binary")), 1, 2);
    backendLayout->addWidget(daemonPathEdit_, 1, 3);
    backendLayout->addWidget(new QLabel(QStringLiteral("Data Dir")), 2, 0);
    backendLayout->addWidget(dataDirEdit_, 2, 1);
    backendLayout->addWidget(new QLabel(QStringLiteral("Wallet File")), 2, 2);
    backendLayout->addWidget(walletPathEdit_, 2, 3);
    backendLayout->addWidget(new QLabel(QStringLiteral("Wallet Pass")), 3, 0);
    backendLayout->addWidget(walletPassEdit_, 3, 1);
    backendLayout->addWidget(new QLabel(QStringLiteral("Current Status")), 3, 2);
    backendLayout->addWidget(new QLabel(QStringLiteral("See header / status bar")), 3, 3);
    backendLayout->addWidget(connectButton, 4, 0);
    backendLayout->addWidget(saveButton, 4, 1);
    backendLayout->addWidget(startButton, 4, 2);
    backendLayout->addWidget(stopButton, 4, 3);
    settingsRoot->addWidget(connectionBox);

    auto* systemLogBox = new QGroupBox(QStringLiteral("System Log"), settingsPage_);
    auto* systemLogLayout = new QVBoxLayout(systemLogBox);
    systemLogView_ = new QPlainTextEdit(systemLogBox);
    systemLogView_->setReadOnly(true);
    systemLogView_->setPlaceholderText(QStringLiteral("Backend, reconciliation, and connection logs will appear here."));
    systemLogView_->setStyleSheet(
        "QPlainTextEdit { background: #000000; color: #f2f2f2; border: 1px solid #202020; border-radius: 2px; "
        "font-family: Menlo, Monaco, monospace; font-size: 12px; selection-background-color: #2d2d2d; }");
    systemLogLayout->addWidget(systemLogView_);
    settingsRoot->addWidget(systemLogBox, 1);

    auto* minerOutputRoot = new QVBoxLayout(minerOutputPage);
    minerOutputRoot->setContentsMargins(12, 12, 12, 12);
    minerOutputRoot->setSpacing(12);
    auto* minerOutputBox = new QGroupBox(QStringLiteral("Live Miner Console"), minerOutputPage);
    auto* minerOutputLayout = new QVBoxLayout(minerOutputBox);
    minerOutputView_ = new QPlainTextEdit(minerOutputBox);
    minerOutputView_->setReadOnly(true);
    minerOutputView_->setPlaceholderText(QStringLiteral("Miner output will appear here."));
    minerOutputView_->setStyleSheet(
        "QPlainTextEdit { background: #050505; color: #37ff5c; border: 1px solid #1d3a1f; border-radius: 2px; "
        "font-family: Menlo, Monaco, monospace; font-size: 12px; selection-background-color: #1e4f23; }");
    minerOutputLayout->addWidget(minerOutputView_);
    minerOutputRoot->addWidget(minerOutputBox, 1);

    tabs_->addTab(dashboardPage_, style()->standardIcon(QStyle::SP_DirHomeIcon), QStringLiteral("Overview"));
    tabs_->addTab(networkGraphPage_, style()->standardIcon(QStyle::SP_BrowserReload), QStringLiteral("Network Graph"));
    tabs_->addTab(walletPage_, style()->standardIcon(QStyle::SP_DriveHDIcon), QStringLiteral("Wallet"));
    tabs_->addTab(chatPage_, style()->standardIcon(QStyle::SP_MessageBoxInformation), QStringLiteral("Chat"));
    tabs_->addTab(miningPage_, style()->standardIcon(QStyle::SP_MediaPlay), QStringLiteral("Mining"));
    tabs_->addTab(minerOutputPage, style()->standardIcon(QStyle::SP_ComputerIcon), QStringLiteral("Miner Output"));
    tabs_->addTab(terminalPage_, style()->standardIcon(QStyle::SP_TitleBarShadeButton), QStringLiteral("Terminal"));
    tabs_->addTab(rpcConsolePage_, style()->standardIcon(QStyle::SP_FileDialogContentsView), QStringLiteral("RPC Console"));
    tabs_->addTab(settingsPage_, style()->standardIcon(QStyle::SP_FileDialogDetailedView), QStringLiteral("Settings"));
    root->addWidget(tabs_, 1);

    setCentralWidget(central);
    statusBar()->showMessage(QStringLiteral("Ready"));

    startupOverlay_ = new QWidget(central);
    startupOverlay_->setObjectName(QStringLiteral("startupOverlay"));
    startupOverlay_->hide();

    startupPanel_ = new QFrame(startupOverlay_);
    startupPanel_->setObjectName(QStringLiteral("startupPanel"));

    auto* overlayLayout = new QVBoxLayout(startupPanel_);
    overlayLayout->setContentsMargins(24, 20, 24, 16);
    overlayLayout->setSpacing(16);

    auto* introRow = new QHBoxLayout();
    introRow->setSpacing(16);
    auto* warningIcon = new QLabel(startupPanel_);
    warningIcon->setPixmap(style()->standardIcon(QStyle::SP_MessageBoxWarning).pixmap(44, 44));
    warningIcon->setAlignment(Qt::AlignTop | Qt::AlignHCenter);
    introRow->addWidget(warningIcon, 0, Qt::AlignTop);

    auto* introTextLayout = new QVBoxLayout();
    introTextLayout->setSpacing(8);
    startupIntroLabel_ = new QLabel(
        QStringLiteral("Recent wallet and transaction data may not yet be complete because CryptEX is still synchronizing with the network."),
        startupPanel_);
    startupIntroLabel_->setObjectName(QStringLiteral("startupTitle"));
    startupIntroLabel_->setWordWrap(true);
    startupSummaryLabel_ = new QLabel(
        QStringLiteral("The node is fetching headers and blocks from peers. The overview, wallet balance, and history will settle as soon as synchronization finishes."),
        startupPanel_);
    startupSummaryLabel_->setObjectName(QStringLiteral("startupBody"));
    startupSummaryLabel_->setWordWrap(true);
    introTextLayout->addWidget(startupIntroLabel_);
    introTextLayout->addWidget(startupSummaryLabel_);
    introRow->addLayout(introTextLayout, 1);
    overlayLayout->addLayout(introRow);

    auto* metricsLayout = new QGridLayout();
    metricsLayout->setHorizontalSpacing(18);
    metricsLayout->setVerticalSpacing(10);

    auto makeMetricLabel = [this](const QString& text) {
        auto* label = new QLabel(text, startupPanel_);
        label->setObjectName(QStringLiteral("startupMetric"));
        return label;
    };
    auto makeMetricValue = [this]() {
        auto* label = new QLabel(QStringLiteral("-"), startupPanel_);
        label->setObjectName(QStringLiteral("startupValue"));
        return label;
    };

    startupBlocksLeftLabel_ = makeMetricValue();
    startupLastBlockLabel_ = makeMetricValue();
    startupProgressLabel_ = makeMetricValue();
    startupRateLabel_ = makeMetricValue();
    startupEtaLabel_ = makeMetricValue();
    startupStateLabel_ = makeMetricValue();

    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Number of blocks left")), 0, 0);
    metricsLayout->addWidget(startupBlocksLeftLabel_, 0, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Last block time")), 1, 0);
    metricsLayout->addWidget(startupLastBlockLabel_, 1, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Progress")), 2, 0);
    metricsLayout->addWidget(startupProgressLabel_, 2, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Progress per hour")), 3, 0);
    metricsLayout->addWidget(startupRateLabel_, 3, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Estimated time left until synced")), 4, 0);
    metricsLayout->addWidget(startupEtaLabel_, 4, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("State")), 5, 0);
    metricsLayout->addWidget(startupStateLabel_, 5, 1);
    overlayLayout->addLayout(metricsLayout);

    startupProgressBar_ = new QProgressBar(startupPanel_);
    startupProgressBar_->setRange(0, 1000);
    startupProgressBar_->setValue(0);
    startupProgressBar_->setFormat(QStringLiteral("%p%"));
    overlayLayout->addWidget(startupProgressBar_);

    auto* overlayFooter = new QHBoxLayout();
    overlayFooter->addStretch(1);
    startupHideButton_ = new QPushButton(QStringLiteral("Close"), startupPanel_);
    startupHideButton_->setObjectName(QStringLiteral("startupHideButton"));
    overlayFooter->addWidget(startupHideButton_);
    overlayLayout->addLayout(overlayFooter);

    connect(startupHideButton_, &QPushButton::clicked, this, [this]() {
        syncOverlayDismissed_ = true;
        setStartupOverlayVisible(false);
        syncOverlayPinned_ = false;
    });
    connect(syncDetailsButton_, &QPushButton::clicked, this, [this]() {
        if (startupOverlay_->isVisible()) {
            syncOverlayDismissed_ = true;
            syncOverlayPinned_ = false;
            setStartupOverlayVisible(false);
        } else {
            syncOverlayDismissed_ = false;
            syncOverlayPinned_ = true;
            refreshSyncState();
        }
    });
    layoutStartupOverlay();

    connect(connectButton, &QPushButton::clicked, this, [this]() {
        applyAutomaticBackendDefaults();
        applyConfigBackedDefaults();
        applyRpcSettings();
        bootstrapBackendAndRefresh();
    });
    connect(saveButton, &QPushButton::clicked, this, [this]() { saveSettings(); });
    connect(startButton, &QPushButton::clicked, this, [this]() { startBackend(); });
    connect(stopButton, &QPushButton::clicked, this, [this]() { stopBackend(); });
    connect(refreshButton, &QPushButton::clicked, this, [this]() { refreshAll(); });
    connect(networkCombo_, &QComboBox::currentTextChanged, this, [this](const QString&) {
        syncOverlayDismissed_ = false;
        lastSyncProgress_ = -1.0;
        lastSyncSampleMs_ = 0;
        applyAutomaticBackendDefaults();
        applyConfigBackedDefaults();
        applyRpcSettings();
        refreshSyncState();
    });
    connect(dataDirEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
        syncWalletPathFromDataDir();
        applyConfigBackedDefaults();
    });
}

void MainWindow::resizeEvent(QResizeEvent* event) {
    QMainWindow::resizeEvent(event);
    layoutStartupOverlay();
}

void MainWindow::layoutStartupOverlay() {
    if (!startupOverlay_ || !startupPanel_ || !tabs_) {
        return;
    }

    const QRect overlayRect = tabs_->geometry();
    startupOverlay_->setGeometry(overlayRect);

    const int maxWidth = qMin(720, qMax(620, overlayRect.width() - 80));
    const int panelWidth = qMin(maxWidth, qMax(560, overlayRect.width() - 60));
    const int panelHeight = qMin(360, qMax(300, overlayRect.height() - 70));
    const int x = qMax(20, (overlayRect.width() - panelWidth) / 2);
    const int y = qMax(24, (overlayRect.height() - panelHeight) / 2 - 20);
    startupPanel_->setGeometry(x, y, panelWidth, panelHeight);
    startupOverlay_->raise();
}

void MainWindow::setStartupOverlayVisible(bool visible) {
    if (!startupOverlay_) {
        return;
    }
    startupOverlay_->setVisible(visible);
    if (syncDetailsButton_) {
        syncDetailsButton_->setText(visible ? QStringLiteral("Hide Sync") : QStringLiteral("Sync Details"));
    }
    if (visible) {
        layoutStartupOverlay();
        startupOverlay_->raise();
    }
}

QString MainWindow::formatSyncEta(double hoursRemaining) const {
    if (!std::isfinite(hoursRemaining) || hoursRemaining <= 0.0) {
        return QStringLiteral("calculating...");
    }
    if (hoursRemaining < (1.0 / 60.0)) {
        return QStringLiteral("less than a minute");
    }

    const int totalMinutes = qMax(1, static_cast<int>(std::round(hoursRemaining * 60.0)));
    if (totalMinutes < 60) {
        return QStringLiteral("%1 minute%2").arg(totalMinutes).arg(totalMinutes == 1 ? QString() : QStringLiteral("s"));
    }

    const int totalHours = totalMinutes / 60;
    const int days = totalHours / 24;
    const int hours = totalHours % 24;
    if (days > 0) {
        if (hours == 0) {
            return QStringLiteral("%1 day%2").arg(days).arg(days == 1 ? QString() : QStringLiteral("s"));
        }
        return QStringLiteral("%1 day%2 %3 hour%4")
            .arg(days)
            .arg(days == 1 ? QString() : QStringLiteral("s"))
            .arg(hours)
            .arg(hours == 1 ? QString() : QStringLiteral("s"));
    }

    return QStringLiteral("%1 hour%2")
        .arg(totalHours)
        .arg(totalHours == 1 ? QString() : QStringLiteral("s"));
}

QString MainWindow::formatSyncTimestamp(qint64 epochSeconds) const {
    if (epochSeconds <= 0) {
        return QStringLiteral("Unknown");
    }
    return QDateTime::fromSecsSinceEpoch(epochSeconds).toString(QStringLiteral("ddd MMM d hh:mm:ss yyyy"));
}

void MainWindow::updateSyncOverlay(const QJsonObject& blockchainInfo) {
    const qint64 blocks = blockchainInfo.value(QStringLiteral("blocks")).toInteger();
    const qint64 headers = blockchainInfo.value(QStringLiteral("headers")).toInteger();
    const qint64 bestPeerHeight = blockchainInfo.value(QStringLiteral("bestpeerheight")).toInteger();
    const qint64 blocksLeft = blockchainInfo.value(QStringLiteral("blocksleft")).toInteger();
    const qint64 medianTime = blockchainInfo.value(QStringLiteral("mediantime")).toInteger();
    const bool ibd = blockchainInfo.value(QStringLiteral("initialblockdownload")).toBool();
    const double verificationProgress = qBound(0.0, blockchainInfo.value(QStringLiteral("verificationprogress")).toDouble(0.0), 1.0);

    const bool syncingHeaders = headers > blocks;
    const bool syncingBlocks = blocksLeft > 0 || bestPeerHeight > blocks;
    const bool shouldShow = backendBootstrapInProgress_ || ibd || syncingHeaders || syncingBlocks || verificationProgress < 0.999;

    const auto stateText = backendBootstrapInProgress_
        ? QStringLiteral("Starting backend...")
        : (!shouldShow ? QStringLiteral("Synchronized with network.")
                       : (syncingHeaders ? QStringLiteral("Syncing headers with network...")
                                         : QStringLiteral("Synchronizing with network...")));

    if (!shouldShow) {
        startupIntroLabel_->setText(QStringLiteral("CryptEX is fully synchronized with the network."));
        startupSummaryLabel_->setText(QStringLiteral("This panel stays available until you close it, so you can inspect the final sync state whenever you want."));
    } else {
        startupIntroLabel_->setText(
            QStringLiteral("Recent wallet and transaction data may not yet be visible, and your wallet balance may be incomplete until CryptEX finishes synchronizing with the network."));
        startupSummaryLabel_->setText(
            QStringLiteral("Information will correct once the wallet has finished syncing with peers. Attempting to spend outputs affected by not-yet-displayed transactions may not be accepted by the network."));
    }
    startupBlocksLeftLabel_->setText(QString::number(qMax<qint64>(0, blocksLeft)));
    startupLastBlockLabel_->setText(formatSyncTimestamp(medianTime));
    startupProgressLabel_->setText(QStringLiteral("%1%").arg(QString::number(verificationProgress * 100.0, 'f', 2)));
    startupStateLabel_->setText(stateText);

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    QString rateText = QStringLiteral("calculating...");
    QString etaText = QStringLiteral("calculating...");
    if (!backendBootstrapInProgress_ && shouldShow) {
        if (lastSyncProgress_ >= 0.0 && lastSyncSampleMs_ > 0 && verificationProgress > lastSyncProgress_) {
            const double elapsedHours = static_cast<double>(nowMs - lastSyncSampleMs_) / 3600000.0;
            if (elapsedHours > 0.0) {
                const double progressPerHour = ((verificationProgress - lastSyncProgress_) * 100.0) / elapsedHours;
                if (progressPerHour > 0.0 && std::isfinite(progressPerHour)) {
                    rateText = QStringLiteral("%1%").arg(QString::number(progressPerHour, 'f', 2));
                    etaText = formatSyncEta((100.0 - (verificationProgress * 100.0)) / progressPerHour);
                }
            }
        }

    }

    if (!shouldShow) {
        rateText = QStringLiteral("synced");
        etaText = QStringLiteral("none");
    }

    lastSyncProgress_ = verificationProgress;
    lastSyncSampleMs_ = nowMs;

    startupRateLabel_->setText(rateText);
    startupEtaLabel_->setText(etaText);

    if (backendBootstrapInProgress_) {
        startupProgressBar_->setRange(0, 0);
    } else {
        startupProgressBar_->setRange(0, 1000);
        startupProgressBar_->setValue(static_cast<int>(std::round(verificationProgress * 1000.0)));
    }

    if (shouldShow && !syncOverlayDismissed_) {
        syncOverlayPinned_ = true;
    }

    if (syncOverlayPinned_ && !syncOverlayDismissed_) {
        setStartupOverlayVisible(true);
    } else if (!shouldShow) {
        setStartupOverlayVisible(false);
    }
    statusBar()->showMessage(!shouldShow
        ? QStringLiteral("Synchronized with network.")
        : QStringLiteral("%1 %2 complete").arg(stateText, startupProgressLabel_->text()));
}

void MainWindow::refreshSyncState() {
    if (backendBootstrapInProgress_) {
        startupIntroLabel_->setText(QStringLiteral("CryptEX is starting the backend and preparing the wallet state."));
        startupSummaryLabel_->setText(QStringLiteral("The GUI will attach to the local RPC server as soon as it becomes available."));
        startupBlocksLeftLabel_->setText(QStringLiteral("-"));
        startupLastBlockLabel_->setText(QStringLiteral("-"));
        startupProgressLabel_->setText(QStringLiteral("Starting..."));
        startupRateLabel_->setText(QStringLiteral("-"));
        startupEtaLabel_->setText(QStringLiteral("calculating..."));
        startupStateLabel_->setText(QStringLiteral("Starting backend..."));
        startupProgressBar_->setRange(0, 0);
        if (!syncOverlayDismissed_) {
            syncOverlayPinned_ = true;
            setStartupOverlayVisible(true);
        }
        return;
    }

    rpc_.call(QStringLiteral("getblockchaininfo"), {}, this,
        [this](const QJsonValue& result) {
            updateSyncOverlay(result.toObject());
        },
        [this](const QString&) {
            if (daemon_.isRunning()) {
                startupIntroLabel_->setText(QStringLiteral("CryptEX is connected to the backend process, but synchronization details are not available yet."));
                startupSummaryLabel_->setText(QStringLiteral("This usually settles after the RPC server finishes its initial startup."));
                startupBlocksLeftLabel_->setText(QStringLiteral("-"));
                startupLastBlockLabel_->setText(QStringLiteral("-"));
                startupProgressLabel_->setText(QStringLiteral("Waiting..."));
                startupRateLabel_->setText(QStringLiteral("-"));
                startupEtaLabel_->setText(QStringLiteral("calculating..."));
                startupStateLabel_->setText(QStringLiteral("Waiting for synchronization state..."));
                startupProgressBar_->setRange(0, 0);
                if (!syncOverlayDismissed_) {
                    syncOverlayPinned_ = true;
                    setStartupOverlayVisible(true);
                }
            } else if (!syncOverlayPinned_) {
                setStartupOverlayVisible(false);
            }
        });
}

QString MainWindow::guessedDaemonPath() const {
    const auto appDir = QCoreApplication::applicationDirPath();
#ifdef Q_OS_MACOS
    const QStringList candidates{appDir + QStringLiteral("/cryptexd_osx"), appDir + QStringLiteral("/../cryptexd_osx")};
#elif defined(Q_OS_WIN)
    const QStringList candidates{appDir + QStringLiteral("/cryptexd_win32.exe"), appDir + QStringLiteral("/../cryptexd_win32.exe")};
#else
    const QStringList candidates{appDir + QStringLiteral("/cryptexd_linux"), appDir + QStringLiteral("/../cryptexd_linux")};
#endif
    for (const auto& candidate : candidates) {
        if (QFileInfo::exists(candidate)) return QDir::cleanPath(candidate);
    }
    return {};
}

QString MainWindow::defaultDataDirForNetwork(const QString& network) const {
    QString baseDir;
#ifdef Q_OS_WIN
    baseDir = qEnvironmentVariable("APPDATA");
    if (baseDir.isEmpty()) {
        const auto userProfile = qEnvironmentVariable("USERPROFILE");
        if (!userProfile.isEmpty()) {
            baseDir = QDir(userProfile).filePath(QStringLiteral("AppData/Roaming"));
        }
    }
#elif defined(Q_OS_MACOS)
    baseDir = QDir::home().filePath(QStringLiteral("Library/Application Support"));
#else
    baseDir = qEnvironmentVariable("XDG_DATA_HOME");
    if (baseDir.isEmpty()) {
        baseDir = QDir::home().filePath(QStringLiteral(".local/share"));
    }
#endif
    if (baseDir.isEmpty()) {
        baseDir = QDir::current().filePath(QStringLiteral("data"));
    } else {
        baseDir = QDir(baseDir).filePath(QStringLiteral("CryptEX"));
    }

    if (network == QStringLiteral("testnet")) {
        return QDir(baseDir).filePath(QStringLiteral("testnet"));
    }
    if (network == QStringLiteral("regtest")) {
        return QDir(baseDir).filePath(QStringLiteral("regtest"));
    }
    return QDir::cleanPath(baseDir);
}

QString MainWindow::defaultWalletPathForDataDir(const QString& dataDir) const {
    if (dataDir.trimmed().isEmpty()) return QStringLiteral("Wallet.dat");
    return QDir(dataDir).filePath(QStringLiteral("Wallet.dat"));
}

QString MainWindow::defaultConfigPathForDataDir(const QString& dataDir) const {
    if (dataDir.trimmed().isEmpty()) return QStringLiteral("cryptex.conf");
    return QDir(dataDir).filePath(QStringLiteral("cryptex.conf"));
}

QString MainWindow::defaultMinerDataDirForDataDir(const QString& dataDir) const {
    if (dataDir.trimmed().isEmpty()) return QStringLiteral("gui-miner");
    return QDir(dataDir).filePath(QStringLiteral("gui-miner"));
}

QUrl MainWindow::defaultRpcUrlForNetwork(const QString& network) const {
    QUrl url(QStringLiteral("http://127.0.0.1/"));
    if (network == QStringLiteral("testnet")) url.setPort(19332);
    else if (network == QStringLiteral("regtest")) url.setPort(19443);
    else url.setPort(9332);
    return url;
}

void MainWindow::applyAutomaticBackendDefaults() {
    const auto network = networkCombo_->currentText().trimmed();

    const auto daemonGuess = guessedDaemonPath();
    const auto currentDaemon = daemonPathEdit_->text().trimmed();
    if (currentDaemon.isEmpty() || (!autoDaemonPath_.isEmpty() && currentDaemon == autoDaemonPath_)) {
        daemonPathEdit_->setText(daemonGuess);
    }
    autoDaemonPath_ = daemonGuess;

    const auto nextDataDir = QDir::cleanPath(defaultDataDirForNetwork(network));
    const auto currentDataDir = QDir::cleanPath(dataDirEdit_->text().trimmed());
    if (currentDataDir.isEmpty() || (!autoDataDir_.isEmpty() && currentDataDir == QDir::cleanPath(autoDataDir_))) {
        dataDirEdit_->setText(nextDataDir);
    }
    autoDataDir_ = nextDataDir;

    const auto effectiveDataDir = dataDirEdit_->text().trimmed().isEmpty() ? nextDataDir : QDir::cleanPath(dataDirEdit_->text().trimmed());
    const auto nextWalletPath = QDir::cleanPath(defaultWalletPathForDataDir(effectiveDataDir));
    const auto currentWalletPath = QDir::cleanPath(walletPathEdit_->text().trimmed());
    if (currentWalletPath.isEmpty() || (!autoWalletPath_.isEmpty() && currentWalletPath == QDir::cleanPath(autoWalletPath_))) {
        walletPathEdit_->setText(nextWalletPath);
    }
    autoWalletPath_ = nextWalletPath;

    const auto nextRpcUrl = defaultRpcUrlForNetwork(network).toString();
    const auto currentRpcUrl = rpcUrlEdit_->text().trimmed();
    if (currentRpcUrl.isEmpty() || (!autoRpcUrl_.isEmpty() && currentRpcUrl == autoRpcUrl_)) {
        rpcUrlEdit_->setText(nextRpcUrl);
    }
    autoRpcUrl_ = nextRpcUrl;
}

void MainWindow::applyConfigBackedDefaults() {
    const auto dataDir = dataDirEdit_->text().trimmed();
    if (dataDir.isEmpty()) {
        return;
    }

    const auto entries = loadSimpleConfig(defaultConfigPathForDataDir(dataDir));
    if (entries.isEmpty()) {
        return;
    }

    const auto configRpcUser = entries.value(QStringLiteral("rpcuser")).trimmed();
    const auto currentRpcUser = rpcUserEdit_->text().trimmed();
    if (!configRpcUser.isEmpty() &&
        (currentRpcUser.isEmpty() || (!autoRpcUser_.isEmpty() && currentRpcUser == autoRpcUser_))) {
        rpcUserEdit_->setText(configRpcUser);
        autoRpcUser_ = configRpcUser;
    }

    const auto configRpcPassword = entries.value(QStringLiteral("rpcpassword"));
    const auto currentRpcPassword = rpcPasswordEdit_->text();
    if (!configRpcPassword.isEmpty() &&
        (currentRpcPassword.isEmpty() || (!autoRpcPassword_.isEmpty() && currentRpcPassword == autoRpcPassword_))) {
        rpcPasswordEdit_->setText(configRpcPassword);
        autoRpcPassword_ = configRpcPassword;
    }

    auto rpcUrl = QUrl(rpcUrlEdit_->text().trimmed());
    if (!rpcUrl.isValid() || rpcUrl.isEmpty()) {
        rpcUrl = defaultRpcUrlForNetwork(networkCombo_->currentText());
    }
    if (entries.contains(QStringLiteral("rpcbind"))) {
        rpcUrl.setHost(loopbackRpcHostForBind(entries.value(QStringLiteral("rpcbind"))));
    }
    if (entries.contains(QStringLiteral("rpcport"))) {
        bool ok = false;
        const auto port = entries.value(QStringLiteral("rpcport")).toUShort(&ok);
        if (ok && port > 0) {
            rpcUrl.setPort(port);
        }
    }
    const auto nextRpcUrl = rpcUrl.toString();
    const auto currentRpcUrl = rpcUrlEdit_->text().trimmed();
    if (currentRpcUrl.isEmpty() || (!autoRpcUrl_.isEmpty() && currentRpcUrl == autoRpcUrl_)) {
        rpcUrlEdit_->setText(nextRpcUrl);
    }
    autoRpcUrl_ = nextRpcUrl;

    const auto walletValue = entries.value(QStringLiteral("wallet")).trimmed();
    if (!walletValue.isEmpty()) {
        QString resolvedWallet = walletValue;
        if (QFileInfo(walletValue).isRelative()) {
            resolvedWallet = QDir(dataDir).filePath(walletValue);
        }
        resolvedWallet = QDir::cleanPath(resolvedWallet);
        const auto currentWalletPath = QDir::cleanPath(walletPathEdit_->text().trimmed());
        if (currentWalletPath.isEmpty() ||
            (!autoWalletPath_.isEmpty() && currentWalletPath == QDir::cleanPath(autoWalletPath_))) {
            walletPathEdit_->setText(resolvedWallet);
        }
        autoWalletPath_ = resolvedWallet;
    }
}

void MainWindow::syncWalletPathFromDataDir() {
    const auto currentWalletPath = QDir::cleanPath(walletPathEdit_->text().trimmed());
    if (!currentWalletPath.isEmpty() && (autoWalletPath_.isEmpty() || currentWalletPath != QDir::cleanPath(autoWalletPath_))) {
        return;
    }

    const auto currentDataDir = dataDirEdit_->text().trimmed();
    const auto nextWalletPath = QDir::cleanPath(defaultWalletPathForDataDir(currentDataDir));
    walletPathEdit_->setText(nextWalletPath);
    autoWalletPath_ = nextWalletPath;
}

void MainWindow::loadSettings() {
    QSettings settings(QStringLiteral("CryptEX"), QStringLiteral("CryptEXQt"));
    rpcUrlEdit_->setText(settings.value(QStringLiteral("rpc/url"), rpcUrlEdit_->text()).toString());
    rpcUserEdit_->setText(settings.value(QStringLiteral("rpc/user"), rpcUserEdit_->text()).toString());
    daemonPathEdit_->setText(settings.value(QStringLiteral("backend/executable"), daemonPathEdit_->text()).toString());
    dataDirEdit_->setText(settings.value(QStringLiteral("backend/datadir")).toString());
    walletPathEdit_->setText(settings.value(QStringLiteral("backend/wallet")).toString());
    networkCombo_->setCurrentText(settings.value(QStringLiteral("backend/network"), QStringLiteral("mainnet")).toString());
    applyAutomaticBackendDefaults();
    applyConfigBackedDefaults();
}

void MainWindow::saveSettings() {
    QSettings settings(QStringLiteral("CryptEX"), QStringLiteral("CryptEXQt"));
    settings.setValue(QStringLiteral("rpc/url"), rpcUrlEdit_->text().trimmed());
    settings.setValue(QStringLiteral("rpc/user"), rpcUserEdit_->text().trimmed());
    settings.setValue(QStringLiteral("backend/executable"), daemonPathEdit_->text().trimmed());
    settings.setValue(QStringLiteral("backend/datadir"), dataDirEdit_->text().trimmed());
    settings.setValue(QStringLiteral("backend/wallet"), walletPathEdit_->text().trimmed());
    settings.setValue(QStringLiteral("backend/network"), networkCombo_->currentText());
    setConnectionStatus(QStringLiteral("GUI settings saved."));
}

void MainWindow::applyRpcSettings() {
    RpcClient::Settings settings;
    settings.url = QUrl(rpcUrlEdit_->text().trimmed());
    settings.username = rpcUserEdit_->text().trimmed();
    settings.password = rpcPasswordEdit_->text();
    rpc_.setSettings(settings);
    setConnectionStatus(QStringLiteral("RPC settings applied."));
}

void MainWindow::bootstrapBackendAndRefresh(int retries) {
    rpc_.call(QStringLiteral("getnetworkinfo"), {}, this,
        [this](const QJsonValue&) {
            backendBootstrapInProgress_ = false;
            setBackendState(QStringLiteral("Connected"));
            setConnectionStatus(QStringLiteral("Connected to cryptexd backend."));
            refreshSyncState();
            refreshAll();
        },
        [this, retries](const QString& error) {
            const auto daemonPath = daemonPathEdit_->text().trimmed();
            if (!daemon_.isRunning() && !daemonPath.isEmpty()) {
                backendBootstrapInProgress_ = true;
                setBackendState(QStringLiteral("Starting backend..."));
                refreshSyncState();
                startBackend();
            }

            if (backendBootstrapInProgress_ && retries > 0) {
                setBackendState(QStringLiteral("Waiting for RPC..."));
                setConnectionStatus(QStringLiteral("Waiting for cryptexd backend to accept RPC..."));
                refreshSyncState();
                QTimer::singleShot(1000, this, [this, retries]() { bootstrapBackendAndRefresh(retries - 1); });
                return;
            }

            backendBootstrapInProgress_ = false;
            setBackendState(QStringLiteral("Backend unavailable"), true);
            setConnectionStatus(error, true);
            refreshSyncState();
        });
}

void MainWindow::setBackendState(const QString& text, bool error) {
    daemonStatusLabel_->setText(text);
    if (error) {
        daemonStatusLabel_->setStyleSheet(QStringLiteral("color:#d36b6b; font-weight:600;"));
    } else if (text.contains(QStringLiteral("Waiting"), Qt::CaseInsensitive) ||
               text.contains(QStringLiteral("Starting"), Qt::CaseInsensitive)) {
        daemonStatusLabel_->setStyleSheet(QStringLiteral("color:#e1d49a; font-weight:600;"));
    } else {
        daemonStatusLabel_->setStyleSheet(QStringLiteral("color:#8ed0a2; font-weight:600;"));
    }
}

void MainWindow::refreshAll() {
    refreshSyncState();
    if (backendBootstrapInProgress_) return;
    reconcilePendingMinedBlocks();
    dashboardPage_->refresh();
    networkGraphPage_->refresh();
    walletPage_->refresh();
    chatPage_->refresh();
    miningPage_->refresh();
}

void MainWindow::reconcilePendingMinedBlocks() {
    if (reconcileInProgress_) {
        return;
    }

    const auto minerDataDir = defaultMinerDataDirForDataDir(dataDirEdit_->text().trimmed());
    QDir blocksDir(QDir(minerDataDir).filePath(QStringLiteral("blocks")));
    if (!blocksDir.exists()) {
        return;
    }

    reconcileInProgress_ = true;
    rpc_.call(QStringLiteral("getblockcount"), {}, this,
        [this, blocksDir](const QJsonValue& result) mutable {
            const auto backendHeight = static_cast<quint64>(result.toInteger());
            QList<QPair<quint64, QString>> pending;
            const auto names = blocksDir.entryList(QStringList{QStringLiteral("blk*.dat")}, QDir::Files, QDir::Name);
            for (const auto& name : names) {
                const auto height = parseBlockHeightFromFileName(name);
                if (height == 0 || height <= backendHeight) {
                    continue;
                }
                pending.push_back({height, blocksDir.filePath(name)});
            }

            if (pending.isEmpty()) {
                reconcileInProgress_ = false;
                return;
            }

            std::sort(pending.begin(), pending.end(), [](const auto& a, const auto& b) {
                return a.first < b.first;
            });

            auto pendingShared = std::make_shared<QList<QPair<quint64, QString>>>(std::move(pending));
            auto submitNext = std::make_shared<std::function<void()>>();
            *submitNext = [this, pendingShared, submitNext]() {
                if (pendingShared->isEmpty()) {
                    reconcileInProgress_ = false;
                    QTimer::singleShot(250, this, [this]() {
                        dashboardPage_->refresh();
                        walletPage_->refresh();
                        miningPage_->refresh();
                    });
                    return;
                }

                const auto nextEntry = pendingShared->takeFirst();
                const auto height = nextEntry.first;
                const auto path = nextEntry.second;
                QFile file(path);
                if (!file.open(QIODevice::ReadOnly)) {
                    systemLogView_->appendPlainText(QStringLiteral("[gui] failed to open pending mined block: ") + path);
                    (*submitNext)();
                    return;
                }

                const auto raw = file.readAll();
                const auto payloadLength = parseStoredBlockLength(raw);
                const int headerBytes = static_cast<int>(sizeof(quint32) + sizeof(quint64));
                if (payloadLength == 0 || raw.size() < headerBytes || raw.size() < headerBytes + static_cast<int>(payloadLength)) {
                    systemLogView_->appendPlainText(QStringLiteral("[gui] invalid mined block file: ") + path);
                    (*submitNext)();
                    return;
                }

                const auto blockHex = QString::fromLatin1(raw.mid(headerBytes, static_cast<int>(payloadLength)).toHex());
                rpc_.call(QStringLiteral("submitblock"), QJsonArray{blockHex}, this,
                    [this, height, submitNext](const QJsonValue& response) {
                        const auto status = response.toString();
                        systemLogView_->appendPlainText(QStringLiteral("[gui] reconciled mined block height %1 -> %2").arg(height).arg(status));
                        (*submitNext)();
                    },
                    [this, height, submitNext](const QString& error) {
                        systemLogView_->appendPlainText(QStringLiteral("[gui] failed to reconcile mined block height %1: %2").arg(height).arg(error));
                        (*submitNext)();
                    });
            };
            (*submitNext)();
        },
        [this](const QString&) {
            reconcileInProgress_ = false;
        });
}

void MainWindow::submitMinedBlockToBackend(const QString& blockHex) {
    const auto trimmed = blockHex.trimmed();
    if (trimmed.isEmpty()) {
        return;
    }

    rpc_.call(QStringLiteral("submitblock"), QJsonArray{trimmed}, this,
        [this](const QJsonValue& result) {
            const auto status = result.toString().trimmed();
            if (status == QStringLiteral("accepted") || status == QStringLiteral("duplicate")) {
                setBackendState(QStringLiteral("Connected"));
                setConnectionStatus(QStringLiteral("Backend accepted mined block (%1).").arg(status));
                QTimer::singleShot(250, this, [this]() { refreshAll(); });
            } else {
                setConnectionStatus(QStringLiteral("Backend returned submitblock status: %1").arg(status), true);
                QTimer::singleShot(500, this, [this]() { refreshAll(); });
            }
        },
        [this](const QString& error) {
            setConnectionStatus(QStringLiteral("Failed to submit mined block to backend: %1").arg(error), true);
            QTimer::singleShot(1000, this, [this]() { refreshAll(); });
        });
}

void MainWindow::startBackend() {
    applyAutomaticBackendDefaults();
    applyConfigBackedDefaults();
    if (rpcUserEdit_->text().trimmed().isEmpty()) {
        rpcUserEdit_->setText(QStringLiteral("cryptexqt"));
        autoRpcUser_ = rpcUserEdit_->text().trimmed();
    }
    if (rpcPasswordEdit_->text().isEmpty()) {
        const auto generated = QString::number(QRandomGenerator::global()->generate64(), 16) +
                               QString::number(QRandomGenerator::global()->generate64(), 16);
        rpcPasswordEdit_->setText(generated);
        autoRpcPassword_ = generated;
    }
    applyRpcSettings();
    saveSettings();
    DaemonController::LaunchConfig config;
    config.executablePath = daemonPathEdit_->text().trimmed().isEmpty() ? guessedDaemonPath() : daemonPathEdit_->text().trimmed();
    config.network = networkCombo_->currentText();
    config.dataDir = dataDirEdit_->text().trimmed().isEmpty()
        ? defaultDataDirForNetwork(config.network)
        : dataDirEdit_->text().trimmed();
    config.rpcBind = QStringLiteral("127.0.0.1");
    config.rpcPort = QUrl(rpcUrlEdit_->text().trimmed()).port(9332);
    config.rpcUser = rpcUserEdit_->text().trimmed();
    config.rpcPassword = rpcPasswordEdit_->text();
    config.walletPath = walletPathEdit_->text().trimmed().isEmpty()
        ? defaultWalletPathForDataDir(config.dataDir)
        : walletPathEdit_->text().trimmed();
    config.walletPassword = walletPassEdit_->text();
    config.debug = true;
    daemon_.startNode(config);
    backendBootstrapInProgress_ = true;
    syncOverlayDismissed_ = false;
    setBackendState(QStringLiteral("Starting backend..."));
    setConnectionStatus(QStringLiteral("Launching cryptexd backend..."));
    refreshSyncState();
    QTimer::singleShot(1500, this, [this]() { bootstrapBackendAndRefresh(20); });
}

void MainWindow::stopBackend() {
    daemon_.stopNode();
    backendBootstrapInProgress_ = false;
    syncOverlayDismissed_ = false;
    setBackendState(QStringLiteral("Backend stopped"));
    setConnectionStatus(QStringLiteral("Stopping backend..."));
    setStartupOverlayVisible(false);
}

void MainWindow::setConnectionStatus(const QString& text, bool error) {
    statusBar()->showMessage(text);
    statusBar()->setStyleSheet(error ? QStringLiteral("color:#d36b6b;") : QStringLiteral("color:#dddddd;"));
}

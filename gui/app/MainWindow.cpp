#include "MainWindow.hpp"
#include "views/DashboardPage.hpp"
#include "views/SendPage.hpp"
#include "views/ReceivePage.hpp"
#include "views/TransactionsPage.hpp"
#include "views/NetworkGraphPage.hpp"
#include "views/WalletPage.hpp"
#include "views/ChatPage.hpp"
#include "views/MiningPage.hpp"
#include "views/RpcConsolePage.hpp"
#include "views/TerminalPage.hpp"
#include "app/NodeWindow.hpp"

#include <QApplication>
#include <QAction>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QFrame>
#include <QCloseEvent>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QPainter>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QScrollArea>
#include <QSettings>
#include <QShowEvent>
#include <QStatusBar>
#include <QStyle>
#include <QTableWidget>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <QToolButton>
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

void writeSimpleConfig(const QString& path, const QHash<QString, QString>& values) {
    QFileInfo info(path);
    QDir().mkpath(info.dir().absolutePath());

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        return;
    }

    QTextStream out(&file);
    auto keys = values.keys();
    std::sort(keys.begin(), keys.end());
    for (const auto& key : keys) {
        out << key << '=' << values.value(key) << '\n';
    }
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

QString formatCoinAmount(qint64 sats) {
    const qint64 whole = sats / 100000000LL;
    const qint64 frac = qAbs(sats % 100000000LL);
    return QStringLiteral("%1.%2 CryptEX")
        .arg(whole)
        .arg(frac, 8, 10, QLatin1Char('0'));
}

QString normalizePeerEntry(QString value) {
    value = value.trimmed();
    if (value.startsWith(QStringLiteral("tcp://"), Qt::CaseInsensitive)) {
        value.remove(0, 6);
    }
    if (value.startsWith(QStringLiteral("http://"), Qt::CaseInsensitive)) {
        value.remove(0, 7);
    }
    if (value.startsWith(QStringLiteral("https://"), Qt::CaseInsensitive)) {
        value.remove(0, 8);
    }
    return value.trimmed();
}

QIcon statusIcon(const QString& resourcePath, const QSize& size = QSize(18, 18)) {
    QIcon icon(resourcePath);
    if (icon.isNull()) {
        return QIcon();
    }
    return QIcon(icon.pixmap(size));
}

QIcon makeAdaptiveIcon(const QString& resourcePath, const QColor& color, const QSize& size = QSize(28, 28)) {
    QIcon baseIcon(resourcePath);
    QPixmap source = baseIcon.pixmap(size);
    if (source.isNull()) {
        source = QPixmap(resourcePath);
    }
    if (source.isNull()) {
        return QIcon(resourcePath);
    }

    QImage tinted = source.toImage().convertToFormat(QImage::Format_ARGB32_Premultiplied);
    QPainter painter(&tinted);
    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(tinted.rect(), color);
    painter.end();

    return QIcon(QPixmap::fromImage(tinted));
}

QScrollArea* makeScrollableTab(QWidget* page, QWidget* parent) {
    auto* scroll = new QScrollArea(parent);
    scroll->setWidget(page);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    // FIX: Ensure the widget inside expands properly
    page->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    scroll->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContentsOnFirstShow);
    scroll->setStyleSheet(QStringLiteral("QScrollArea { background: transparent; border: none; }"));
    return scroll;
}

bool isRpcAuthError(const QString& error) {
    const auto lowered = error.toLower();
    return lowered.contains(QStringLiteral("401")) ||
           lowered.contains(QStringLiteral("403")) ||
           lowered.contains(QStringLiteral("unauthorized")) ||
           lowered.contains(QStringLiteral("authentication")) ||
           lowered.contains(QStringLiteral("forbidden"));
}

bool isRetryableRpcStartupError(const QString& error) {
    const auto lowered = error.toLower();
    return lowered.contains(QStringLiteral("connection refused")) ||
           lowered.contains(QStringLiteral("connection closed")) ||
           lowered.contains(QStringLiteral("connection timed out")) ||
           lowered.contains(QStringLiteral("host not found")) ||
           lowered.contains(QStringLiteral("server not found")) ||
           lowered.contains(QStringLiteral("remote host closed"));
}

bool isAddressInUseError(const QString& line) {
    return line.contains(QStringLiteral("address already in use"), Qt::CaseInsensitive) ||
           line.contains(QStringLiteral("bind:"), Qt::CaseInsensitive);
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
        if (isAddressInUseError(line)) {
            handleBackendPortConflict();
        }
    });
    connect(&daemon_, &DaemonController::errorLine, this, [this](const QString& line) {
        systemLogView_->appendPlainText(QStringLiteral("[daemon-error] ") + line);
        if (isAddressInUseError(line)) {
            handleBackendPortConflict();
        }
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
    refreshTimer_->setInterval(15000);
    connect(refreshTimer_, &QTimer::timeout, this, [this]() { refreshAll(); });

    refreshCooldownTimer_ = new QTimer(this);
    refreshCooldownTimer_->setSingleShot(true);
    refreshCooldownTimer_->setInterval(1500);
    connect(refreshCooldownTimer_, &QTimer::timeout, this, [this]() {
        refreshWaveInFlight_ = false;
        if (refreshWaveQueued_) {
            refreshWaveQueued_ = false;
            refreshAll();
        }
    });

    startupProgressPulseTimer_ = new QTimer(this);
    startupProgressPulseTimer_->setInterval(120);
    connect(startupProgressPulseTimer_, &QTimer::timeout, this, [this]() {
        if (!startupProgressBar_) {
            return;
        }
        startupProgressPulseValue_ += (startupProgressPulseDirection_ * 90);
        if (startupProgressPulseValue_ >= 840) {
            startupProgressPulseValue_ = 840;
            startupProgressPulseDirection_ = -1;
        } else if (startupProgressPulseValue_ <= 180) {
            startupProgressPulseValue_ = 180;
            startupProgressPulseDirection_ = 1;
        }
        startupProgressBar_->setValue(startupProgressPulseValue_);
    });

    if (systemLogView_) {
        systemLogView_->appendPlainText(QStringLiteral("[gui] GUI initialized"));
        systemLogView_->appendPlainText(QStringLiteral("[gui] Current RPC target: %1").arg(rpcUrlEdit_->text().trimmed()));
    }

    const int bootstrapGeneration = backendBootstrapGeneration_;
    QTimer::singleShot(0, this, [this, bootstrapGeneration]() {
        if (bootstrapGeneration == backendBootstrapGeneration_) {
            bootstrapBackendAndRefresh(8, bootstrapGeneration);
        }
    });
}

void MainWindow::buildUi() {
    setWindowTitle(QStringLiteral("CryptEX Core - Satoshi"));
    resize(860, 560);
    setMinimumSize(760, 500);

    auto* fileMenu = menuBar()->addMenu(QStringLiteral("&File"));
    auto* settingsMenu = menuBar()->addMenu(QStringLiteral("&Settings"));
    auto* windowMenu = menuBar()->addMenu(QStringLiteral("&Window"));
    auto* helpMenu = menuBar()->addMenu(QStringLiteral("&Help"));

    auto* openNodeAction = windowMenu->addAction(QStringLiteral("Node Window"));
    auto* openWalletManagerAction = windowMenu->addAction(QStringLiteral("Wallet Manager"));
    auto* refreshAction = fileMenu->addAction(QStringLiteral("Refresh"));
    auto* syncAction = settingsMenu->addAction(QStringLiteral("Sync Details"));
    fileMenu->addSeparator();
    auto* quitAction = fileMenu->addAction(QStringLiteral("Quit"));
    auto* aboutAction = helpMenu->addAction(QStringLiteral("About CryptEX Core"));

    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    tabs_ = new QTabWidget(central);
    tabs_->tabBar()->setDocumentMode(true);
    tabs_->tabBar()->setExpanding(false);
    tabs_->setIconSize(QSize(24, 24));
    tabs_->setMovable(false);

    const bool darkUi = palette().window().color().lightness() < 128;
    const QColor iconTint = darkUi ? QColor(QStringLiteral("#f3f3f3"))
                                   : QColor(QStringLiteral("#2d2d2d"));

    dashboardPage_ = new DashboardPage(tabs_);
    sendPage_ = new SendPage(tabs_);
    receivePage_ = new ReceivePage(tabs_);
    transactionsPage_ = new TransactionsPage(tabs_);
    networkGraphPage_ = new NetworkGraphPage(this);
    walletPage_ = new WalletPage(this);
    chatPage_ = new ChatPage(this);
    miningPage_ = new MiningPage(this);
    rpcConsolePage_ = new RpcConsolePage(this);
    terminalPage_ = new TerminalPage(this);
    settingsPage_ = new QWidget(this);
    walletManagerPage_ = new QWidget(this);
    nodeInfoPage_ = new QWidget(this);
    consoleHubPage_ = new QWidget(this);
    minerOutputPage_ = new QWidget(this);
    nodeWindow_ = new NodeWindow(this);

    dashboardPage_->setRpcClient(&rpc_);
    sendPage_->setRpcClient(&rpc_);
    receivePage_->setRpcClient(&rpc_);
    transactionsPage_->setRpcClient(&rpc_);
    networkGraphPage_->setRpcClient(&rpc_);
    walletPage_->setRpcClient(&rpc_);
    chatPage_->setRpcClient(&rpc_);
    miningPage_->setRpcClient(&rpc_);
    rpcConsolePage_->setRpcClient(&rpc_);
    miningPage_->setMinerController(&miner_);
    connect(walletPage_, &WalletPage::walletTypeChanged, this, [this]() {
        refreshWalletSessionState();
        refreshWalletRegistry();
        receivePage_->refresh();
        transactionsPage_->refresh();
    });

    rpcUrlEdit_ = new QLineEdit(QStringLiteral("http://127.0.0.1:9332/"), settingsPage_);
    rpcUserEdit_ = new QLineEdit(QStringLiteral("admin"), settingsPage_);
    rpcPasswordEdit_ = new QLineEdit(settingsPage_);
    rpcPasswordEdit_->setEchoMode(QLineEdit::Password);
    daemonPathEdit_ = new QLineEdit(guessedDaemonPath(), settingsPage_);
    dataDirEdit_ = new QLineEdit(settingsPage_);
    walletNameEdit_ = new QLineEdit(walletManagerPage_);
    walletPathEdit_ = new QLineEdit(walletManagerPage_);
    walletPassEdit_ = new QLineEdit(walletManagerPage_);
    walletPassEdit_->setEchoMode(QLineEdit::Password);
    walletFormatCombo_ = new QComboBox(walletManagerPage_);
    walletFormatCombo_->addItem(QStringLiteral("Base64 (CryptEX native)"), QStringLiteral("base64"));
    walletFormatCombo_->addItem(QStringLiteral("Base58 (P2PKH style)"), QStringLiteral("base58"));
    walletFormatCombo_->addItem(QStringLiteral("0x Hex (EVM style)"), QStringLiteral("hex"));
    walletFormatCombo_->addItem(QStringLiteral("Bech32"), QStringLiteral("bech32"));
    walletListTable_ = new QTableWidget(walletManagerPage_);
    walletRootValue_ = new QLabel(QStringLiteral("-"), walletManagerPage_);
    directPeersEdit_ = new QLineEdit(settingsPage_);
    seedPeersEdit_ = new QLineEdit(settingsPage_);
    directPeersEdit_->setPlaceholderText(QStringLiteral("Optional direct peers, comma-separated"));
    seedPeersEdit_->setPlaceholderText(QStringLiteral("Leave blank to use automatic global discovery"));
    networkCombo_ = new QComboBox(settingsPage_);
    networkCombo_->addItems({QStringLiteral("mainnet"), QStringLiteral("testnet"), QStringLiteral("regtest")});

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
    auto* backendSettingsLayout = new QGridLayout(connectionBox);
    auto* connectButton = new QPushButton(QStringLiteral("Connect"), connectionBox);
    auto* saveButton = new QPushButton(QStringLiteral("Save"), connectionBox);
    auto* startButton = new QPushButton(QStringLiteral("Start Backend"), connectionBox);
    auto* stopButton = new QPushButton(QStringLiteral("Stop Backend"), connectionBox);
    backendSettingsLayout->addWidget(new QLabel(QStringLiteral("Network")), 0, 0);
    backendSettingsLayout->addWidget(networkCombo_, 0, 1);
    backendSettingsLayout->addWidget(new QLabel(QStringLiteral("RPC URL")), 0, 2);
    backendSettingsLayout->addWidget(rpcUrlEdit_, 0, 3);
    backendSettingsLayout->addWidget(new QLabel(QStringLiteral("RPC User")), 1, 0);
    backendSettingsLayout->addWidget(rpcUserEdit_, 1, 1);
    backendSettingsLayout->addWidget(new QLabel(QStringLiteral("RPC Password")), 1, 2);
    backendSettingsLayout->addWidget(rpcPasswordEdit_, 1, 3);
    backendSettingsLayout->addWidget(new QLabel(QStringLiteral("Daemon Binary")), 2, 0);
    backendSettingsLayout->addWidget(daemonPathEdit_, 2, 1);
    backendSettingsLayout->addWidget(new QLabel(QStringLiteral("Data Dir")), 2, 2);
    backendSettingsLayout->addWidget(dataDirEdit_, 2, 3);
    backendSettingsLayout->addWidget(new QLabel(QStringLiteral("Direct Peer(s)")), 3, 0);
    backendSettingsLayout->addWidget(directPeersEdit_, 3, 1);
    backendSettingsLayout->addWidget(new QLabel(QStringLiteral("Seed DNS / Peers")), 3, 2);
    backendSettingsLayout->addWidget(seedPeersEdit_, 3, 3);
    backendSettingsLayout->addWidget(connectButton, 4, 0);
    backendSettingsLayout->addWidget(saveButton, 4, 1);
    backendSettingsLayout->addWidget(startButton, 4, 2);
    backendSettingsLayout->addWidget(stopButton, 4, 3);
    backendSettingsLayout->setColumnStretch(1, 1);
    backendSettingsLayout->setColumnStretch(3, 1);
    settingsRoot->addWidget(connectionBox);

    auto* walletManagerRoot = new QVBoxLayout(walletManagerPage_);
    walletManagerRoot->setContentsMargins(12, 12, 12, 12);
    walletManagerRoot->setSpacing(12);

    auto* walletDirectoryBox = new QGroupBox(QStringLiteral("Managed Wallet Directory"), walletManagerPage_);
    auto* walletDirectoryLayout = new QFormLayout(walletDirectoryBox);
    walletSessionStatusLabel_ = new QLabel(QStringLiteral("No wallet open"), walletManagerPage_);
    walletSessionStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    walletRootValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    walletDirectoryLayout->addRow(QStringLiteral("Wallet root"), walletRootValue_);
    walletDirectoryLayout->addRow(QStringLiteral("Session"), walletSessionStatusLabel_);
    walletManagerRoot->addWidget(walletDirectoryBox);

    auto* walletCreateBox = new QGroupBox(QStringLiteral("Create Or Open Wallet"), walletManagerPage_);
    auto* walletCreateLayout = new QGridLayout(walletCreateBox);
    createWalletButton_ = new QPushButton(QStringLiteral("Create Wallet"), walletCreateBox);
    openWalletButton_ = new QPushButton(QStringLiteral("Open Selected"), walletCreateBox);
    closeWalletButton_ = new QPushButton(QStringLiteral("Close Wallet"), walletCreateBox);
    deleteWalletButton_ = new QPushButton(QStringLiteral("Delete Selected"), walletCreateBox);
    refreshWalletsButton_ = new QPushButton(QStringLiteral("Refresh Wallets"), walletCreateBox);
    walletNameEdit_->setPlaceholderText(QStringLiteral("Wallet name"));
    walletPassEdit_->setPlaceholderText(QStringLiteral("Per-wallet passcode"));
    walletPathEdit_->setVisible(false);
    walletCreateLayout->addWidget(new QLabel(QStringLiteral("Wallet name")), 0, 0);
    walletCreateLayout->addWidget(walletNameEdit_, 0, 1);
    walletCreateLayout->addWidget(new QLabel(QStringLiteral("Wallet type")), 0, 2);
    walletCreateLayout->addWidget(walletFormatCombo_, 0, 3);
    walletCreateLayout->addWidget(new QLabel(QStringLiteral("Passcode")), 1, 0);
    walletCreateLayout->addWidget(walletPassEdit_, 1, 1, 1, 3);
    walletCreateLayout->addWidget(createWalletButton_, 2, 0);
    walletCreateLayout->addWidget(openWalletButton_, 2, 1);
    walletCreateLayout->addWidget(closeWalletButton_, 2, 2);
    walletCreateLayout->addWidget(deleteWalletButton_, 2, 3);
    walletCreateLayout->addWidget(refreshWalletsButton_, 3, 0, 1, 4);
    walletCreateLayout->setColumnStretch(1, 1);
    walletCreateLayout->setColumnStretch(3, 1);
    walletManagerRoot->addWidget(walletCreateBox);

    auto* walletListBox = new QGroupBox(QStringLiteral("Available Wallets"), walletManagerPage_);
    auto* walletListLayout = new QVBoxLayout(walletListBox);
    walletListTable_->setColumnCount(4);
    walletListTable_->setHorizontalHeaderLabels({QStringLiteral("Name"),
                                                 QStringLiteral("Type"),
                                                 QStringLiteral("Wallet File"),
                                                 QStringLiteral("Active")});
    walletListTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    walletListTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    walletListTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    walletListTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    walletListTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    walletListTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    walletListTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    walletListTable_->setWordWrap(false);
    walletListLayout->addWidget(walletListTable_);
    walletManagerRoot->addWidget(walletListBox, 1);

    auto* checkpointBox = new QGroupBox(QStringLiteral("Checkpoint Manager"), settingsPage_);
    auto* checkpointLayout = new QGridLayout(checkpointBox);
    checkpointModeValue_ = new QLabel(QStringLiteral("-"), checkpointBox);
    checkpointHeightValue_ = new QLabel(QStringLiteral("-"), checkpointBox);
    checkpointHashValue_ = new QLabel(QStringLiteral("-"), checkpointBox);
    checkpointGuardValue_ = new QLabel(QStringLiteral("-"), checkpointBox);
    portMappingValue_ = new QLabel(QStringLiteral("-"), checkpointBox);
    checkpointModeValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    checkpointHeightValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    checkpointHashValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    checkpointGuardValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    portMappingValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    checkpointPinButton_ = new QPushButton(QStringLiteral("Pin Current Tip"), checkpointBox);
    checkpointClearButton_ = new QPushButton(QStringLiteral("Clear Pin"), checkpointBox);
    checkpointRefreshButton_ = new QPushButton(QStringLiteral("Refresh Checkpoint"), checkpointBox);
    checkpointLayout->addWidget(new QLabel(QStringLiteral("Mode")), 0, 0);
    checkpointLayout->addWidget(checkpointModeValue_, 0, 1);
    checkpointLayout->addWidget(new QLabel(QStringLiteral("Height")), 1, 0);
    checkpointLayout->addWidget(checkpointHeightValue_, 1, 1);
    checkpointLayout->addWidget(new QLabel(QStringLiteral("Hash")), 2, 0);
    checkpointLayout->addWidget(checkpointHashValue_, 2, 1);
    checkpointLayout->addWidget(new QLabel(QStringLiteral("Reorg Guard")), 3, 0);
    checkpointLayout->addWidget(checkpointGuardValue_, 3, 1);
    checkpointLayout->addWidget(new QLabel(QStringLiteral("Port Mapping")), 4, 0);
    checkpointLayout->addWidget(portMappingValue_, 4, 1);
    checkpointLayout->addWidget(checkpointPinButton_, 5, 0);
    checkpointLayout->addWidget(checkpointClearButton_, 5, 1);
    checkpointLayout->addWidget(checkpointRefreshButton_, 5, 2);
    checkpointLayout->setColumnStretch(1, 1);
    settingsRoot->addWidget(checkpointBox);
    settingsRoot->addStretch(1);

    auto* nodeInfoLayout = new QVBoxLayout(nodeInfoPage_);
    nodeInfoLayout->setContentsMargins(12, 12, 12, 12);
    nodeInfoLayout->setSpacing(12);
    auto* infoTitle = new QLabel(QStringLiteral("Node information"), nodeInfoPage_);
    infoTitle->setObjectName(QStringLiteral("pageTitle"));
    nodeInfoLayout->addWidget(infoTitle);
    auto* infoBox = new QGroupBox(QStringLiteral("General"), nodeInfoPage_);
    auto* infoForm = new QFormLayout(infoBox);
    nodeClientVersionValue_ = new QLabel(QStringLiteral("-"), infoBox);
    nodeRpcTargetValue_ = new QLabel(QStringLiteral("-"), infoBox);
    nodeDataDirValue_ = new QLabel(QStringLiteral("-"), infoBox);
    nodeNetworkValue_ = new QLabel(QStringLiteral("-"), infoBox);
    nodeConnectionValue_ = new QLabel(QStringLiteral("-"), infoBox);
    nodeHeightValue_ = new QLabel(QStringLiteral("-"), infoBox);
    nodeSyncValue_ = new QLabel(QStringLiteral("-"), infoBox);
    nodeApprovalValue_ = new QLabel(QStringLiteral("-"), infoBox);
    nodeMempoolValue_ = new QLabel(QStringLiteral("-"), infoBox);
    nodePeerModeValue_ = new QLabel(QStringLiteral("-"), infoBox);
    for (auto* label : {nodeClientVersionValue_, nodeRpcTargetValue_, nodeDataDirValue_, nodeNetworkValue_,
                        nodeConnectionValue_, nodeHeightValue_, nodeSyncValue_, nodeApprovalValue_,
                        nodeMempoolValue_, nodePeerModeValue_}) {
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label->setWordWrap(true);
    }
    infoForm->addRow(QStringLiteral("Client"), nodeClientVersionValue_);
    infoForm->addRow(QStringLiteral("RPC target"), nodeRpcTargetValue_);
    infoForm->addRow(QStringLiteral("Datadir"), nodeDataDirValue_);
    infoForm->addRow(QStringLiteral("Network"), nodeNetworkValue_);
    infoForm->addRow(QStringLiteral("Connections"), nodeConnectionValue_);
    infoForm->addRow(QStringLiteral("Current height"), nodeHeightValue_);
    infoForm->addRow(QStringLiteral("Sync state"), nodeSyncValue_);
    infoForm->addRow(QStringLiteral("Chain approval"), nodeApprovalValue_);
    infoForm->addRow(QStringLiteral("Mempool"), nodeMempoolValue_);
    infoForm->addRow(QStringLiteral("Peer bootstrap"), nodePeerModeValue_);
    nodeInfoLayout->addWidget(infoBox);
    nodeInfoLayout->addStretch(1);

    auto* consoleHubLayout = new QVBoxLayout(consoleHubPage_);
    consoleHubLayout->setContentsMargins(12, 12, 12, 12);
    consoleHubLayout->setSpacing(12);
    auto* consoleTabs = new QTabWidget(consoleHubPage_);
    consoleTabs->tabBar()->setDocumentMode(true);
    consoleTabs->tabBar()->setExpanding(false);

    auto* systemLogPage = new QWidget(consoleTabs);
    auto* systemLogLayout = new QVBoxLayout(systemLogPage);
    systemLogLayout->setContentsMargins(0, 0, 0, 0);
    systemLogView_ = new QPlainTextEdit(systemLogPage);
    systemLogView_->setReadOnly(true);
    systemLogView_->setPlaceholderText(QStringLiteral("Backend, peer bootstrap, reconciliation, and connection logs will appear here."));
    systemLogView_->setStyleSheet(
        "QPlainTextEdit { background: #000000; color: #f2f2f2; border: 1px solid #202020; border-radius: 2px; "
        "font-family: Menlo, Monaco, monospace; font-size: 12px; selection-background-color: #2d2d2d; }");
    systemLogLayout->addWidget(systemLogView_);

    auto* minerOutputLayout = new QVBoxLayout(minerOutputPage_);
    minerOutputLayout->setContentsMargins(0, 0, 0, 0);
    minerOutputView_ = new QPlainTextEdit(minerOutputPage_);
    minerOutputView_->setReadOnly(true);
    minerOutputView_->setPlaceholderText(QStringLiteral("Miner output will appear here."));
    minerOutputView_->setStyleSheet(
        "QPlainTextEdit { background: #050505; color: #37ff5c; border: 1px solid #1d3a1f; border-radius: 2px; "
        "font-family: Menlo, Monaco, monospace; font-size: 12px; selection-background-color: #1e4f23; }");
    minerOutputLayout->addWidget(minerOutputView_);

    consoleTabs->addTab(rpcConsolePage_, QIcon(QStringLiteral(":/branding/icons/console.svg")), QStringLiteral("RPC"));
    consoleHubLayout->addWidget(consoleTabs);

    tabs_->addTab(makeScrollableTab(dashboardPage_, tabs_), makeAdaptiveIcon(QStringLiteral(":/branding/icons/overview.png"), iconTint, QSize(26, 26)), QStringLiteral("Overview"));
    tabs_->addTab(makeScrollableTab(sendPage_, tabs_), makeAdaptiveIcon(QStringLiteral(":/branding/icons/send.png"), iconTint, QSize(26, 26)), QStringLiteral("Send"));
    tabs_->addTab(makeScrollableTab(receivePage_, tabs_), makeAdaptiveIcon(QStringLiteral(":/branding/icons/receive.png"), iconTint, QSize(26, 26)), QStringLiteral("Receive"));
    tabs_->addTab(makeScrollableTab(transactionsPage_, tabs_), makeAdaptiveIcon(QStringLiteral(":/branding/icons/transactions.png"), iconTint, QSize(24, 24)), QStringLiteral("Transactions"));
    root->addWidget(tabs_, 1);
    setCentralWidget(central);

    nodeWindow_->setSection(QStringLiteral("information"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/node.svg"), iconTint, QSize(20, 20)), QStringLiteral("Information"), makeScrollableTab(nodeInfoPage_, nodeWindow_));
    nodeWindow_->setSection(QStringLiteral("wallets"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/node.svg"), iconTint, QSize(20, 20)), QStringLiteral("Wallet Manager"), makeScrollableTab(walletManagerPage_, nodeWindow_));
    nodeWindow_->setSection(QStringLiteral("wallet"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/node.svg"), iconTint, QSize(20, 20)), QStringLiteral("Wallet Tools"), makeScrollableTab(walletPage_, nodeWindow_));
    nodeWindow_->setSection(QStringLiteral("chat"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/node.svg"), iconTint, QSize(20, 20)), QStringLiteral("Chat"), makeScrollableTab(chatPage_, nodeWindow_));
    nodeWindow_->setSection(QStringLiteral("mining"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/node.svg"), iconTint, QSize(20, 20)), QStringLiteral("Mining"), makeScrollableTab(miningPage_, nodeWindow_));
    nodeWindow_->setSection(QStringLiteral("console"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/console.svg"), iconTint, QSize(20, 20)), QStringLiteral("Console"), consoleHubPage_);
    nodeWindow_->setSection(QStringLiteral("system-log"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/console.svg"), iconTint, QSize(20, 20)), QStringLiteral("System Log"), makeScrollableTab(systemLogPage, nodeWindow_));
    nodeWindow_->setSection(QStringLiteral("terminal"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/console.svg"), iconTint, QSize(20, 20)), QStringLiteral("Terminal"), makeScrollableTab(terminalPage_, nodeWindow_));
    nodeWindow_->setSection(QStringLiteral("miner-output"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/console.svg"), iconTint, QSize(20, 20)), QStringLiteral("Miner Output"), makeScrollableTab(minerOutputPage_, nodeWindow_));
    nodeWindow_->setSection(QStringLiteral("network"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/network.svg"), iconTint, QSize(20, 20)), QStringLiteral("Network"), makeScrollableTab(networkGraphPage_, nodeWindow_));
    nodeWindow_->setSection(QStringLiteral("settings"), makeAdaptiveIcon(QStringLiteral(":/branding/icons/settings.svg"), iconTint, QSize(20, 20)), QStringLiteral("Settings"), makeScrollableTab(settingsPage_, nodeWindow_));

    auto* cornerWidget = new QWidget(tabs_);
    auto* cornerLayout = new QHBoxLayout(cornerWidget);
    cornerLayout->setContentsMargins(0, 0, 4, 0);
    cornerLayout->setSpacing(4);
    nodeWindowButton_ = new QToolButton(cornerWidget);
    nodeWindowButton_->setIcon(makeAdaptiveIcon(QStringLiteral(":/branding/icons/node.svg"), iconTint, QSize(18, 18)));
    nodeWindowButton_->setAutoRaise(true);
    nodeWindowButton_->setToolTip(QStringLiteral("Open Node Window"));
    cornerLayout->addWidget(nodeWindowButton_);
    tabs_->setCornerWidget(cornerWidget, Qt::TopRightCorner);

    daemonStatusLabel_ = new QLabel(QStringLiteral("Node: stopped"), this);
    daemonStatusLabel_->setObjectName(QStringLiteral("valueLabel"));
    approvalBadgeLabel_ = new QLabel(QStringLiteral("Approval unknown"), this);
    approvalBadgeLabel_->setObjectName(QStringLiteral("approvalBadge"));
    approvalStatusBarLabel_ = new QLabel(QStringLiteral("Approval: waiting for backend"), this);
    approvalStatusBarLabel_->setObjectName(QStringLiteral("approvalStatusBar"));
    approvalBadgeLabel_->hide();
    approvalStatusBarLabel_->hide();
    auto* syncStatusStrip = new QWidget(this);
    auto* syncStatusLayout = new QHBoxLayout(syncStatusStrip);
    syncStatusLayout->setContentsMargins(0, 0, 0, 0);
    syncStatusLayout->setSpacing(6);
    syncStatusBarLabel_ = new QLabel(QStringLiteral("Synchronizing with network..."), syncStatusStrip);
    syncStatusBarLabel_->setObjectName(QStringLiteral("syncStatusBarLabel"));
    syncStatusProgressBar_ = new QProgressBar(syncStatusStrip);
    syncStatusProgressBar_->setObjectName(QStringLiteral("syncStatusProgressBar"));
    syncStatusProgressBar_->setFixedWidth(120);
    syncStatusProgressBar_->setFixedHeight(9);
    syncStatusProgressBar_->setTextVisible(false);
    syncStatusProgressBar_->setRange(0, 0);
    syncStatusLayout->addWidget(syncStatusBarLabel_);
    syncStatusLayout->addWidget(syncStatusProgressBar_);
    syncStatusLayout->addStretch(1);
    syncDetailsButton_ = new QToolButton(this);
    syncDetailsButton_->setObjectName(QStringLiteral("statusIconButton"));
    syncDetailsButton_->setAutoRaise(true);
    syncDetailsButton_->setCursor(Qt::PointingHandCursor);
    peerActivityButton_ = new QToolButton(this);
    peerActivityButton_->setObjectName(QStringLiteral("statusIconButton"));
    peerActivityButton_->setAutoRaise(true);
    peerActivityButton_->setCursor(Qt::PointingHandCursor);
    networkActivityButton_ = new QToolButton(this);
    networkActivityButton_->setObjectName(QStringLiteral("statusIconButton"));
    networkActivityButton_->setAutoRaise(true);
    networkActivityButton_->setCursor(Qt::PointingHandCursor);
    statusBar()->addPermanentWidget(syncStatusStrip, 1);
    statusBar()->addPermanentWidget(syncDetailsButton_);
    statusBar()->addPermanentWidget(peerActivityButton_);
    statusBar()->addPermanentWidget(networkActivityButton_);
    statusBar()->addPermanentWidget(daemonStatusLabel_);
    updateApprovalIndicators();
    updateStatusIcons();
    statusBar()->showMessage(QStringLiteral("Ready"));

    startupOverlay_ = new QWidget(central);
    startupOverlay_->setObjectName(QStringLiteral("startupOverlay"));
    startupOverlay_->hide();
    startupPanel_ = new QFrame(startupOverlay_);
    startupPanel_->setObjectName(QStringLiteral("startupPanel"));
    auto* overlayLayout = new QVBoxLayout(startupPanel_);
    overlayLayout->setContentsMargins(22, 18, 22, 14);
    overlayLayout->setSpacing(14);
    auto* introRow = new QHBoxLayout();
    introRow->setSpacing(14);
    auto* warningIcon = new QLabel(startupPanel_);
    warningIcon->setPixmap(style()->standardIcon(QStyle::SP_MessageBoxInformation).pixmap(40, 40));
    introRow->addWidget(warningIcon, 0, Qt::AlignTop);
    auto* introTextLayout = new QVBoxLayout();
    startupIntroLabel_ = new QLabel(QStringLiteral("CryptEX is loading blocks and peer state."), startupPanel_);
    startupIntroLabel_->setObjectName(QStringLiteral("startupTitle"));
    startupIntroLabel_->setWordWrap(true);
    startupSummaryLabel_ = new QLabel(QStringLiteral("Balances, transactions, and network state will settle as sync progresses."), startupPanel_);
    startupSummaryLabel_->setObjectName(QStringLiteral("startupBody"));
    startupSummaryLabel_->setWordWrap(true);
    introTextLayout->addWidget(startupIntroLabel_);
    introTextLayout->addWidget(startupSummaryLabel_);
    introRow->addLayout(introTextLayout, 1);
    overlayLayout->addLayout(introRow);
    auto* metricsLayout = new QGridLayout();
    metricsLayout->setHorizontalSpacing(18);
    metricsLayout->setVerticalSpacing(8);
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
    startupApprovalLabel_ = makeMetricValue();
    startupValidatedPeersLabel_ = makeMetricValue();
    startupLockedBalanceLabel_ = makeMetricValue();
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Blocks left")), 0, 0);
    metricsLayout->addWidget(startupBlocksLeftLabel_, 0, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Last block time")), 1, 0);
    metricsLayout->addWidget(startupLastBlockLabel_, 1, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Progress")), 2, 0);
    metricsLayout->addWidget(startupProgressLabel_, 2, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Progress per hour")), 3, 0);
    metricsLayout->addWidget(startupRateLabel_, 3, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Estimated time left")), 4, 0);
    metricsLayout->addWidget(startupEtaLabel_, 4, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("State")), 5, 0);
    metricsLayout->addWidget(startupStateLabel_, 5, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Chain approval")), 6, 0);
    metricsLayout->addWidget(startupApprovalLabel_, 6, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Validated peers")), 7, 0);
    metricsLayout->addWidget(startupValidatedPeersLabel_, 7, 1);
    metricsLayout->addWidget(makeMetricLabel(QStringLiteral("Locked wallet funds")), 8, 0);
    metricsLayout->addWidget(startupLockedBalanceLabel_, 8, 1);
    overlayLayout->addLayout(metricsLayout);
    startupProgressBar_ = new QProgressBar(startupPanel_);
    startupProgressBar_->setObjectName(QStringLiteral("startupProgressBar"));
    startupProgressBar_->setRange(0, 1000);
    startupProgressBar_->setValue(0);
    startupProgressBar_->setFormat(QStringLiteral("%p%"));
    startupProgressBar_->setAlignment(Qt::AlignCenter);
    startupProgressBar_->setTextVisible(true);
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
    connect(syncDetailsButton_, &QToolButton::clicked, this, [this]() { toggleSyncOverlay(); });
    connect(peerActivityButton_, &QToolButton::clicked, this, [this]() { openNodeWindow(QStringLiteral("network")); });
    connect(networkActivityButton_, &QToolButton::clicked, this, [this]() {
        rpc_.call(QStringLiteral("setnetworkactive"), QJsonArray{!networkActive_}, this,
            [this](const QJsonValue& result) {
                networkActive_ = result.toBool();
                systemLogView_->appendPlainText(QStringLiteral("[gui] network activity %1").arg(networkActive_ ? QStringLiteral("enabled") : QStringLiteral("disabled")));
                refreshSyncState();
                refreshNodeInformation();
                updateStatusIcons();
            },
            [this](const QString& error) {
                if (systemLogView_) {
                    systemLogView_->appendPlainText(QStringLiteral("[gui] failed to toggle network activity: %1").arg(error));
                }
                setConnectionStatus(QStringLiteral("Failed to toggle network activity: %1").arg(error), true);
            });
    });
    layoutStartupOverlay();
    syncOverlayPinned_ = true;
    syncOverlayDismissed_ = false;
    updateSyncStatusBar(QStringLiteral("Synchronizing with network..."), true);

    connect(openNodeAction, &QAction::triggered, this, [this]() { openNodeWindow(); });
    connect(openWalletManagerAction, &QAction::triggered, this, [this]() { openNodeWindow(QStringLiteral("wallets")); });
    connect(refreshAction, &QAction::triggered, this, [this]() { refreshAll(); });
    connect(syncAction, &QAction::triggered, this, [this]() { toggleSyncOverlay(); });
    connect(quitAction, &QAction::triggered, this, [this]() { close(); });
    connect(aboutAction, &QAction::triggered, this, [this]() {
        QMessageBox::information(this,
                                 QStringLiteral("About CryptEX Core"),
                                 QStringLiteral("CryptEX Core keeps the main wallet view focused while advanced node, mining, console, and network tools live in the separate Node window."));
    });
    connect(nodeWindowButton_, &QToolButton::clicked, this, [this]() { openNodeWindow(); });
    connect(tabs_, &QTabWidget::currentChanged, this, [this](int) { refreshCurrentMainTab(); });
    connect(nodeWindow_, &NodeWindow::sectionChanged, this, [this](const QString&) { refreshVisibleNodeSection(); });
    connect(connectButton, &QPushButton::clicked, this, [this]() {
        systemLogView_->appendPlainText(QStringLiteral("[gui] Connect requested for %1").arg(rpcUrlEdit_->text().trimmed()));
        applyAutomaticBackendDefaults();
        applyConfigBackedDefaults();
        applyRpcSettings();
        bootstrapBackendAndRefresh();
    });
    connect(saveButton, &QPushButton::clicked, this, [this]() {
        saveSettings();
        systemLogView_->appendPlainText(QStringLiteral("[gui] Settings saved"));
    });
    connect(startButton, &QPushButton::clicked, this, [this]() { startBackend(); });
    connect(stopButton, &QPushButton::clicked, this, [this]() { stopBackend(); });
    connect(createWalletButton_, &QPushButton::clicked, this, [this]() { createWalletSession(); });
    connect(openWalletButton_, &QPushButton::clicked, this, [this]() { openWalletSession(); });
    connect(closeWalletButton_, &QPushButton::clicked, this, [this]() { closeWalletSession(); });
    connect(deleteWalletButton_, &QPushButton::clicked, this, [this]() { deleteWalletSession(); });
    connect(refreshWalletsButton_, &QPushButton::clicked, this, [this]() { refreshWalletRegistry(); });
    connect(walletListTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
        const auto items = walletListTable_->selectedItems();
        if (items.isEmpty()) {
            walletPathEdit_->clear();
            return;
        }
        const auto row = items.first()->row();
        const auto* nameItem = walletListTable_->item(row, 0);
        const auto* typeItem = walletListTable_->item(row, 1);
        const auto* fileItem = walletListTable_->item(row, 2);
        if (nameItem) {
            walletNameEdit_->setText(nameItem->text());
        }
        if (typeItem) {
            const auto index = walletFormatCombo_->findData(typeItem->text().toLower());
            if (index >= 0) {
                walletFormatCombo_->setCurrentIndex(index);
            }
        }
        if (fileItem) {
            walletPathEdit_->setText(fileItem->data(Qt::UserRole).toString());
        }
    });
    connect(checkpointPinButton_, &QPushButton::clicked, this, [this]() {
        rpc_.call(QStringLiteral("pincheckpoint"), {}, this,
            [this](const QJsonValue&) {
                systemLogView_->appendPlainText(QStringLiteral("[gui] pinned current tip as local checkpoint"));
                refreshCheckpointManager();
                refreshAll();
            },
            [this](const QString& error) {
                systemLogView_->appendPlainText(QStringLiteral("[gui] failed to pin checkpoint: ") + error);
            });
    });
    connect(checkpointClearButton_, &QPushButton::clicked, this, [this]() {
        rpc_.call(QStringLiteral("clearcheckpointpin"), {}, this,
            [this](const QJsonValue&) {
                systemLogView_->appendPlainText(QStringLiteral("[gui] cleared manual checkpoint pin"));
                refreshCheckpointManager();
                refreshAll();
            },
            [this](const QString& error) {
                systemLogView_->appendPlainText(QStringLiteral("[gui] failed to clear checkpoint pin: ") + error);
            });
    });
    connect(checkpointRefreshButton_, &QPushButton::clicked, this, [this]() {
        rpc_.call(QStringLiteral("refreshcheckpoint"), {}, this,
            [this](const QJsonValue&) {
                systemLogView_->appendPlainText(QStringLiteral("[gui] refreshed automatic checkpoint"));
                refreshCheckpointManager();
                refreshAll();
            },
            [this](const QString& error) {
                systemLogView_->appendPlainText(QStringLiteral("[gui] failed to refresh checkpoint: ") + error);
            });
    });
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

    updateResponsiveLayout();
}

void MainWindow::resizeEvent(QResizeEvent* event) {
    QMainWindow::resizeEvent(event);
    updateResponsiveLayout();
    layoutStartupOverlay();
}

void MainWindow::showEvent(QShowEvent* event) {
    QMainWindow::showEvent(event);
    if (!syncOverlayDismissed_) {
        syncOverlayPinned_ = true;
        setStartupOverlayVisible(true);
        QTimer::singleShot(120, this, [this]() {
            if (!syncOverlayDismissed_) {
                layoutStartupOverlay();
                refreshSyncState();
            }
        });
    }
}

void MainWindow::updateResponsiveLayout() {
    if (tabs_) {
        tabs_->setIconSize(width() < 860 ? QSize(18, 18) : QSize(20, 20));
    }
}

void MainWindow::layoutStartupOverlay() {
    if (!startupOverlay_ || !startupPanel_ || !tabs_) {
        return;
    }

    const QRect overlayRect = tabs_->geometry();
    startupOverlay_->setGeometry(overlayRect);

    const int maxWidth = qMin(720, qMax(620, overlayRect.width() - 80));
    const int panelWidth = qMin(maxWidth, qMax(560, overlayRect.width() - 60));
    const int panelHeight = qMin(470, qMax(360, overlayRect.height() - 70));
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
        syncDetailsButton_->setToolTip(visible ? QStringLiteral("Hide sync details")
                                               : QStringLiteral("Show sync details"));
    }
    updateStatusIcons();
    if (visible) {
        layoutStartupOverlay();
        startupOverlay_->raise();
    }
}

void MainWindow::updateSyncStatusBar(const QString& text, bool busy, double progress) {
    if (syncStatusBarLabel_) {
        syncStatusBarLabel_->setText(text);
    }
    if (!syncStatusProgressBar_) {
        updateStatusIcons();
        return;
    }
    if (busy && progress < 0.0) {
        syncStatusProgressBar_->setRange(0, 0);
        updateStatusIcons();
        return;
    }
    syncStatusProgressBar_->setRange(0, 1000);
    const auto clamped = qBound(0.0, progress, 1.0);
    syncStatusProgressBar_->setValue(static_cast<int>(std::round(clamped * 1000.0)));
    updateStatusIcons();
}

void MainWindow::setStartupProgressBusy(bool busy, const QString& text) {
    if (!startupProgressBar_) {
        return;
    }
    if (busy) {
        startupProgressPulseValue_ = 220;
        startupProgressPulseDirection_ = 1;
        startupProgressBar_->setRange(0, 1000);
        startupProgressBar_->setValue(startupProgressPulseValue_);
        startupProgressBar_->setFormat(text.isEmpty() ? QStringLiteral("Starting...") : text);
        startupProgressBar_->setTextVisible(true);
        if (startupProgressPulseTimer_ && !startupProgressPulseTimer_->isActive()) {
            startupProgressPulseTimer_->start();
        }
        return;
    }
    if (startupProgressPulseTimer_ && startupProgressPulseTimer_->isActive()) {
        startupProgressPulseTimer_->stop();
    }
    startupProgressBar_->setRange(0, 1000);
    startupProgressBar_->setFormat(QStringLiteral("%p%"));
    startupProgressBar_->setTextVisible(true);
}

void MainWindow::updateStatusIcons() {
    if (syncDetailsButton_) {
        QString syncIconPath = QStringLiteral(":/branding/icons/synced.png");
        QString syncTooltip = startupOverlay_ && startupOverlay_->isVisible()
            ? QStringLiteral("Hide sync details")
            : QStringLiteral("Show sync details");

        if (backendBootstrapInProgress_) {
            syncIconPath = QStringLiteral(":/branding/icons/clock1.png");
            syncTooltip = QStringLiteral("Backend is starting. Click to show sync details.");
        } else if (networkSyncing_ || lastSyncProgress_ < 0.999) {
            const int phase = std::clamp(static_cast<int>(std::floor(QDateTime::currentMSecsSinceEpoch() / 350.0)) % 5 + 1, 1, 5);
            syncIconPath = QStringLiteral(":/branding/icons/clock%1.png").arg(phase);
            syncTooltip = startupOverlay_ && startupOverlay_->isVisible()
                ? QStringLiteral("Hide sync details")
                : QStringLiteral("Show sync details");
        } else {
            syncTooltip = startupOverlay_ && startupOverlay_->isVisible()
                ? QStringLiteral("Hide sync details")
                : QStringLiteral("Show sync details");
        }

        syncDetailsButton_->setIcon(statusIcon(syncIconPath));
        syncDetailsButton_->setToolTip(syncTooltip);
    }

    if (peerActivityButton_) {
        const int level = connectedPeerCount_ <= 0 ? 0 : std::min(4, connectedPeerCount_);
        peerActivityButton_->setIcon(statusIcon(QStringLiteral(":/branding/icons/connect%1.png").arg(level)));
        peerActivityButton_->setToolTip(QStringLiteral("Show peer activity (%1 connected peer%2)")
            .arg(connectedPeerCount_)
            .arg(connectedPeerCount_ == 1 ? QString() : QStringLiteral("s")));
    }

    if (networkActivityButton_) {
        if (networkActive_) {
            networkActivityButton_->setIcon(statusIcon(QStringLiteral(":/branding/icons/network.svg")));
            networkActivityButton_->setToolTip(QStringLiteral("Disable network activity"));
        } else {
            networkActivityButton_->setIcon(statusIcon(QStringLiteral(":/branding/icons/network_disabled.png")));
            networkActivityButton_->setToolTip(QStringLiteral("Enable network activity"));
        }
    }
}

void MainWindow::toggleSyncOverlay() {
    if (!startupOverlay_) {
        return;
    }
    if (startupOverlay_->isVisible()) {
        syncOverlayDismissed_ = true;
        syncOverlayPinned_ = false;
        setStartupOverlayVisible(false);
        updateStatusIcons();
        return;
    }
    syncOverlayDismissed_ = false;
    syncOverlayPinned_ = true;
    setStartupOverlayVisible(true);
    refreshSyncState();
    updateStatusIcons();
}

void MainWindow::updateApprovalIndicators() {
    QString badgeText;
    QString badgeStyle;
    QString statusText;

    if (backendBootstrapInProgress_) {
        badgeText = QStringLiteral("Sync pending");
        badgeStyle = QStringLiteral("background:#35536f; color:#f3f7fb; border:1px solid #4f7697; border-radius:10px; padding:3px 10px; font-weight:600;");
        statusText = QStringLiteral("Approval: waiting for backend startup");
    } else if (!approvalKnown_) {
        badgeText = QStringLiteral("Approval unknown");
        badgeStyle = QStringLiteral("background:#505050; color:#f0f0f0; border:1px solid #6a6a6a; border-radius:10px; padding:3px 10px; font-weight:600;");
        statusText = QStringLiteral("Approval: waiting for sync and wallet state");
    } else if (!chainApproved_) {
        badgeText = QStringLiteral("Locked until sync approval");
        badgeStyle = QStringLiteral("background:#6a5120; color:#fff1c7; border:1px solid #8a6b2b; border-radius:10px; padding:3px 10px; font-weight:600;");
        statusText = QStringLiteral("Approval: locked, %1 locked, %2 validated peer%3%4")
            .arg(formatCoinAmount(lockedBalanceSats_))
            .arg(validatedPeerCount_)
            .arg(validatedPeerCount_ == 1 ? QString() : QStringLiteral("s"))
            .arg(networkSyncing_ ? QStringLiteral(", syncing") : QString());
    } else if (networkSyncing_) {
        badgeText = QStringLiteral("Approved, syncing");
        badgeStyle = QStringLiteral("background:#2f6048; color:#e3fff0; border:1px solid #4b8a6a; border-radius:10px; padding:3px 10px; font-weight:600;");
        statusText = QStringLiteral("Approval: approved, %1 validated peer%2, syncing")
            .arg(validatedPeerCount_)
            .arg(validatedPeerCount_ == 1 ? QString() : QStringLiteral("s"));
    } else {
        badgeText = QStringLiteral("Chain approved");
        badgeStyle = QStringLiteral("background:#2f6048; color:#e3fff0; border:1px solid #4b8a6a; border-radius:10px; padding:3px 10px; font-weight:600;");
        statusText = QStringLiteral("Approval: approved, %1 validated peer%2")
            .arg(validatedPeerCount_)
            .arg(validatedPeerCount_ == 1 ? QString() : QStringLiteral("s"));
    }

    if (approvalBadgeLabel_) {
        approvalBadgeLabel_->setText(badgeText);
        approvalBadgeLabel_->setStyleSheet(badgeStyle);
    }
    if (approvalStatusBarLabel_) {
        approvalStatusBarLabel_->setText(statusText);
        approvalStatusBarLabel_->setStyleSheet(QStringLiteral("color:#d8ded6; font-weight:600;"));
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
    if (blockchainInfo.contains(QStringLiteral("chain_approved"))) {
        approvalKnown_ = true;
        chainApproved_ = blockchainInfo.value(QStringLiteral("chain_approved")).toBool(false);
        updateApprovalIndicators();
    }

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
        setStartupProgressBusy(true, QStringLiteral("Starting..."));
        updateSyncStatusBar(QStringLiteral("Synchronizing with network..."), true);
    } else {
        setStartupProgressBusy(false);
        startupProgressBar_->setRange(0, 1000);
        startupProgressBar_->setValue(static_cast<int>(std::round(verificationProgress * 1000.0)));
        updateSyncStatusBar(stateText, shouldShow, verificationProgress);
    }

    if (shouldShow && !syncOverlayDismissed_) {
        syncOverlayPinned_ = true;
    }

    if (!syncOverlayDismissed_) {
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
        approvalKnown_ = false;
        chainApproved_ = false;
        lockedBalanceSats_ = 0;
        validatedPeerCount_ = 0;
        networkSyncing_ = true;
        connectedPeerCount_ = 0;
        networkActive_ = true;
        updateApprovalIndicators();
        startupIntroLabel_->setText(QStringLiteral("CryptEX is starting the backend and preparing the wallet state."));
        startupSummaryLabel_->setText(QStringLiteral("The GUI will attach to the local RPC server as soon as it becomes available."));
        startupBlocksLeftLabel_->setText(QStringLiteral("-"));
        startupLastBlockLabel_->setText(QStringLiteral("-"));
        startupProgressLabel_->setText(QStringLiteral("Starting..."));
        startupRateLabel_->setText(QStringLiteral("-"));
        startupEtaLabel_->setText(QStringLiteral("calculating..."));
        startupStateLabel_->setText(QStringLiteral("Starting backend..."));
        startupApprovalLabel_->setText(QStringLiteral("Waiting for backend..."));
        startupValidatedPeersLabel_->setText(QStringLiteral("-"));
        startupLockedBalanceLabel_->setText(QStringLiteral("-"));
        setStartupProgressBusy(true, QStringLiteral("Starting..."));
        updateSyncStatusBar(QStringLiteral("Synchronizing with network..."), true);
        syncOverlayPinned_ = true;
        setStartupOverlayVisible(true);
        updateStatusIcons();
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
                startupApprovalLabel_->setText(QStringLiteral("Waiting for wallet state..."));
                startupValidatedPeersLabel_->setText(QStringLiteral("-"));
                startupLockedBalanceLabel_->setText(QStringLiteral("-"));
                setStartupProgressBusy(true, QStringLiteral("Waiting..."));
                updateSyncStatusBar(QStringLiteral("Synchronizing with network..."), true);
                approvalKnown_ = false;
                chainApproved_ = false;
                networkSyncing_ = true;
                updateApprovalIndicators();
                syncOverlayPinned_ = true;
                setStartupOverlayVisible(true);
                updateStatusIcons();
            } else if (!syncOverlayPinned_) {
                connectedPeerCount_ = 0;
                setStartupOverlayVisible(false);
                updateStatusIcons();
            }
        });

    rpc_.call(QStringLiteral("getnetworkinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            const auto validated = obj.value(QStringLiteral("validatedpeers")).toInteger();
            const auto connected = obj.value(QStringLiteral("connections")).toInteger();
            startupValidatedPeersLabel_->setText(QStringLiteral("%1 validated / %2 connected")
                .arg(validated)
                .arg(connected));
            startupValidatedPeersLabel_->setStyleSheet(QStringLiteral("color:#d8ded6;"));
            validatedPeerCount_ = validated;
            connectedPeerCount_ = connected;
            networkSyncing_ = obj.value(QStringLiteral("syncing")).toBool(false);
            networkActive_ = obj.value(QStringLiteral("networkactive")).toBool(true);
            if (obj.contains(QStringLiteral("chain_approved"))) {
                approvalKnown_ = true;
                chainApproved_ = obj.value(QStringLiteral("chain_approved")).toBool(false);
                startupApprovalLabel_->setText(chainApproved_
                    ? QStringLiteral("Approved")
                    : QStringLiteral("Locked until sync approval"));
                startupApprovalLabel_->setStyleSheet(chainApproved_
                    ? QStringLiteral("color:#8ed0a2;")
                    : QStringLiteral("color:#d6b25e;"));
            }
            updateApprovalIndicators();
            updateStatusIcons();
        },
        [this](const QString&) {
            startupValidatedPeersLabel_->setText(QStringLiteral("Unavailable"));
            startupValidatedPeersLabel_->setStyleSheet(QStringLiteral("color:#d36b6b;"));
            validatedPeerCount_ = 0;
            connectedPeerCount_ = 0;
            networkSyncing_ = false;
            updateApprovalIndicators();
            updateStatusIcons();
        });

    rpc_.call(QStringLiteral("getwalletinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            const auto locked = static_cast<qint64>(obj.value(QStringLiteral("locked_balance_sats")).toInteger());
            if (obj.contains(QStringLiteral("chain_approved"))) {
                approvalKnown_ = true;
                chainApproved_ = obj.value(QStringLiteral("chain_approved")).toBool(false);
                startupApprovalLabel_->setText(chainApproved_
                    ? QStringLiteral("Approved")
                    : QStringLiteral("Locked until sync approval"));
                startupApprovalLabel_->setStyleSheet(chainApproved_
                    ? QStringLiteral("color:#8ed0a2;")
                    : QStringLiteral("color:#d6b25e;"));
            }
            startupLockedBalanceLabel_->setText(formatCoinAmount(locked));
            startupLockedBalanceLabel_->setStyleSheet(locked > 0
                ? QStringLiteral("color:#d6b25e;")
                : QStringLiteral("color:#d8ded6;"));
            lockedBalanceSats_ = locked;
            updateApprovalIndicators();
        },
        [this](const QString& error) {
            if (error.contains(QStringLiteral("no wallet is open"), Qt::CaseInsensitive)) {
                startupLockedBalanceLabel_->setText(QStringLiteral("No wallet open"));
            } else if (error.contains(QStringLiteral("wallet RPC requires"), Qt::CaseInsensitive) ||
                       error.contains(QStringLiteral("walletpass"), Qt::CaseInsensitive)) {
                startupLockedBalanceLabel_->setText(QStringLiteral("Wallet password required"));
            } else {
                startupLockedBalanceLabel_->setText(QStringLiteral("Wallet unavailable"));
            }
            startupLockedBalanceLabel_->setStyleSheet(QStringLiteral("color:#d36b6b;"));
            lockedBalanceSats_ = 0;
            updateApprovalIndicators();
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

QString MainWindow::managedWalletRootForDataDir(const QString& dataDir) const {
    const auto effectiveDataDir = dataDir.trimmed().isEmpty()
        ? defaultDataDirForNetwork(networkCombo_ ? networkCombo_->currentText() : QStringLiteral("mainnet"))
        : QDir::cleanPath(dataDir.trimmed());
    return QDir(effectiveDataDir).filePath(QStringLiteral("wallets"));
}

QString MainWindow::managedWalletPathForName(const QString& walletName, const QString& format) const {
    QString stem = walletName.trimmed();
    if (stem.isEmpty()) {
        stem = QStringLiteral("wallet");
    }
    for (QChar& ch : stem) {
        if (!ch.isLetterOrNumber() && ch != QLatin1Char('-') && ch != QLatin1Char('_')) {
            ch = QLatin1Char('-');
        }
    }
    stem = stem.simplified().replace(QLatin1Char(' '), QLatin1Char('-'));
    while (stem.contains(QStringLiteral("--"))) {
        stem.replace(QStringLiteral("--"), QStringLiteral("-"));
    }
    stem.remove(QRegularExpression(QStringLiteral("^-+|-+$")));
    if (stem.isEmpty()) {
        stem = QStringLiteral("wallet");
    }
    Q_UNUSED(format);
    return QDir(managedWalletRootForDataDir(dataDirEdit_ ? dataDirEdit_->text() : QString())).filePath(stem + QStringLiteral(".dat"));
}

QString MainWindow::legacyWalletPathForDataDir(const QString& dataDir) const {
    const auto effectiveDataDir = dataDir.trimmed().isEmpty()
        ? defaultDataDirForNetwork(networkCombo_ ? networkCombo_->currentText() : QStringLiteral("mainnet"))
        : QDir::cleanPath(dataDir.trimmed());
    return QDir(effectiveDataDir).filePath(QStringLiteral("Wallet.dat"));
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
    if (!configRpcUser.isEmpty()) {
        rpcUserEdit_->setText(configRpcUser);
        autoRpcUser_ = configRpcUser;
    }

    const auto configRpcPassword = entries.value(QStringLiteral("rpcpassword"));
    if (!configRpcPassword.isEmpty()) {
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

    const auto configConnect = normalizePeerEntry(entries.value(QStringLiteral("connect")));
    if (!configConnect.isEmpty()) {
        const auto currentDirectPeers = directPeersEdit_->text().trimmed();
        if (currentDirectPeers.isEmpty() || (!autoDirectPeers_.isEmpty() && currentDirectPeers == autoDirectPeers_)) {
            directPeersEdit_->setText(configConnect);
        }
        autoDirectPeers_ = configConnect;
    }

    const auto configSeed = normalizePeerEntry(entries.value(QStringLiteral("seed")));
    if (!configSeed.isEmpty()) {
        const auto currentSeedPeers = seedPeersEdit_->text().trimmed();
        if (currentSeedPeers.isEmpty() || (!autoSeedPeers_.isEmpty() && currentSeedPeers == autoSeedPeers_)) {
            seedPeersEdit_->setText(configSeed);
        }
        autoSeedPeers_ = configSeed;
    }
}

void MainWindow::syncWalletPathFromDataDir() {
    if (walletRootValue_) {
        walletRootValue_->setText(QDir::cleanPath(managedWalletRootForDataDir(dataDirEdit_ ? dataDirEdit_->text() : QString())));
    }
    if (walletPathEdit_) {
        const auto current = walletPathEdit_->text().trimmed();
        const auto legacy = QDir::cleanPath(legacyWalletPathForDataDir(dataDirEdit_ ? dataDirEdit_->text() : QString()));
        if ((current.isEmpty() || QFileInfo(current).fileName() == QStringLiteral("Wallet.dat")) &&
            QFileInfo::exists(legacy)) {
            walletPathEdit_->setText(legacy);
        }
    }
}

void MainWindow::persistLocalRpcConfig() {
    const auto dataDir = dataDirEdit_->text().trimmed();
    const auto rpcUser = rpcUserEdit_->text().trimmed();
    const auto rpcPassword = rpcPasswordEdit_->text();
    const auto rpcUrl = QUrl(rpcUrlEdit_->text().trimmed());

    if (dataDir.isEmpty() || rpcUser.isEmpty() || rpcPassword.isEmpty()) {
        return;
    }

    const auto configPath = defaultConfigPathForDataDir(dataDir);
    auto entries = loadSimpleConfig(configPath);
    if (entries.value(QStringLiteral("rpcuser")).trimmed() == rpcUser &&
        entries.value(QStringLiteral("rpcpassword")) == rpcPassword &&
        entries.value(QStringLiteral("rpcbind")).trimmed() == QStringLiteral("127.0.0.1") &&
        entries.value(QStringLiteral("rpcport")).trimmed() == QString::number(rpcUrl.port(9332))) {
        return;
    }

    entries.insert(QStringLiteral("rpcuser"), rpcUser);
    entries.insert(QStringLiteral("rpcpassword"), rpcPassword);
    entries.insert(QStringLiteral("rpcbind"), QStringLiteral("127.0.0.1"));
    entries.insert(QStringLiteral("rpcport"), QString::number(rpcUrl.port(9332)));
    writeSimpleConfig(configPath, entries);
}

QStringList MainWindow::parsePeerEntryList(const QString& text) const {
    QString normalized = text;
    normalized.replace('\n', ',');
    normalized.replace(';', ',');
    const auto rawParts = normalized.split(',', Qt::SkipEmptyParts);

    QStringList entries;
    for (const auto& rawPart : rawParts) {
        const auto entry = normalizePeerEntry(rawPart);
        if (!entry.isEmpty() && !entries.contains(entry)) {
            entries.push_back(entry);
        }
    }
    return entries;
}

void MainWindow::refreshWalletSessionState() {
    rpc_.call(QStringLiteral("getwalletsessioninfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            const bool loaded = obj.value(QStringLiteral("wallet_loaded")).toBool(false);
            if (!walletSessionStatusLabel_) {
                return;
            }
            if (!loaded) {
                walletSessionStatusLabel_->setText(QStringLiteral("No wallet open"));
                walletSessionStatusLabel_->setStyleSheet(QStringLiteral("color:#d6b25e;"));
                closeWalletButton_->setEnabled(false);
                if (walletPathEdit_) {
                    const auto legacy = QDir::cleanPath(legacyWalletPathForDataDir(dataDirEdit_ ? dataDirEdit_->text() : QString()));
                    walletPathEdit_->setText(QFileInfo::exists(legacy) ? legacy : QString());
                }
                return;
            }
            const auto walletFile = obj.value(QStringLiteral("walletfile")).toString();
            const auto format = obj.value(QStringLiteral("address_format")).toString();
            const auto address = obj.value(QStringLiteral("primaryaddress")).toString();
            const auto walletRoot = obj.value(QStringLiteral("walletroot")).toString();
            if (!walletRoot.isEmpty() && walletRootValue_) {
                walletRootValue_->setText(walletRoot);
            }
            const auto formatIndex = walletFormatCombo_ ? walletFormatCombo_->findData(format) : -1;
            if (formatIndex >= 0) {
                walletFormatCombo_->setCurrentIndex(formatIndex);
            }
            walletSessionStatusLabel_->setText(QStringLiteral("%1 | %2 | %3").arg(format, address, walletFile));
            walletSessionStatusLabel_->setStyleSheet(QStringLiteral("color:#8ed0a2;"));
            closeWalletButton_->setEnabled(true);
            if (walletPathEdit_) {
                walletPathEdit_->setText(walletFile);
            }
        },
        [this](const QString&) {
            if (!walletSessionStatusLabel_) {
                return;
            }
            walletSessionStatusLabel_->setText(QStringLiteral("Wallet session unavailable until RPC is connected"));
            walletSessionStatusLabel_->setStyleSheet(QStringLiteral("color:#d36b6b;"));
            closeWalletButton_->setEnabled(false);
            if (walletPathEdit_) {
                const auto legacy = QDir::cleanPath(legacyWalletPathForDataDir(dataDirEdit_ ? dataDirEdit_->text() : QString()));
                walletPathEdit_->setText(QFileInfo::exists(legacy) ? legacy : QString());
            }
        });
}

void MainWindow::refreshWalletRegistry() {
    if (walletRootValue_) {
        walletRootValue_->setText(QDir::cleanPath(managedWalletRootForDataDir(dataDirEdit_ ? dataDirEdit_->text() : QString())));
    }
    if (!walletListTable_) {
        return;
    }
    rpc_.call(QStringLiteral("listwallets"), {}, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            walletListTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                auto* nameItem = new QTableWidgetItem(obj.value(QStringLiteral("name")).toString());
                auto* typeItem = new QTableWidgetItem(obj.value(QStringLiteral("address_format")).toString(QStringLiteral("unknown")));
                auto* fileItem = new QTableWidgetItem(QFileInfo(obj.value(QStringLiteral("path")).toString()).fileName());
                auto* activeItem = new QTableWidgetItem(obj.value(QStringLiteral("active")).toBool() ? QStringLiteral("Yes") : QStringLiteral("No"));
                fileItem->setToolTip(obj.value(QStringLiteral("path")).toString());
                fileItem->setData(Qt::UserRole, obj.value(QStringLiteral("path")).toString());
                walletListTable_->setItem(i, 0, nameItem);
                walletListTable_->setItem(i, 1, typeItem);
                walletListTable_->setItem(i, 2, fileItem);
                walletListTable_->setItem(i, 3, activeItem);
            }
        },
        [this](const QString&) {
            walletListTable_->setRowCount(0);
        });
}

void MainWindow::createWalletSession() {
    const auto walletName = walletNameEdit_->text().trimmed();
    const auto walletPass = walletPassEdit_->text();
    const auto walletFormat = walletFormatCombo_->currentData().toString();
    if (walletName.isEmpty() || walletPass.isEmpty()) {
        setConnectionStatus(QStringLiteral("Wallet name and passcode are required to create a wallet."), true);
        return;
    }
    const auto walletPath = QDir::cleanPath(managedWalletPathForName(walletName, walletFormat));
    walletPathEdit_->setText(walletPath);

    // FIX: Ensure RPC credentials are set before calling
    applyRpcSettings();
    persistLocalRpcConfig();

    rpc_.call(QStringLiteral("createwallet"),
              QJsonArray{walletPath, walletPass, walletFormat},
              this,
              [this, walletPath](const QJsonValue& result) {
                  const auto obj = result.toObject();
                  systemLogView_->appendPlainText(QStringLiteral("[gui] created wallet %1").arg(walletPath));
                  const auto mnemonic = obj.value(QStringLiteral("mnemonic")).toString();
                  setConnectionStatus(QStringLiteral("Wallet created and opened."));
                  if (!mnemonic.isEmpty()) {
                      QMessageBox::information(this,
                                               QStringLiteral("Wallet Mnemonic"),
                                               QStringLiteral("Write this recovery phrase down offline before you continue:\n\n%1")
                                                   .arg(mnemonic));
                  }
                  refreshWalletSessionState();
                  refreshWalletRegistry();
                  walletPage_->refresh();
              },
              [this](const QString& error) {
                  if (isRpcAuthError(error)) {
                      setConnectionStatus(QStringLiteral("RPC authentication failed. Check RPC user/password in Settings or cryptex.conf."), true);
                  } else {
                      setConnectionStatus(QStringLiteral("Failed to create wallet: %1").arg(error), true);
                  }
                  if (systemLogView_) {
                      systemLogView_->appendPlainText(QStringLiteral("[gui] wallet create failed: %1").arg(error));
                  }
              });
}

void MainWindow::openWalletSession() {
    auto walletPath = walletPathEdit_->text().trimmed();
    const auto walletPass = walletPassEdit_->text();
    if (walletPath.isEmpty()) {
        const auto legacy = QDir::cleanPath(legacyWalletPathForDataDir(dataDirEdit_ ? dataDirEdit_->text() : QString()));
        if (QFileInfo::exists(legacy)) {
            walletPath = legacy;
            walletPathEdit_->setText(walletPath);
        }
    }
    if (walletPath.isEmpty() || walletPass.isEmpty()) {
        setConnectionStatus(QStringLiteral("Wallet file and passcode are required to open a wallet."), true);
        return;
    }

    // FIX: Ensure RPC credentials are set before calling
    applyRpcSettings();
    persistLocalRpcConfig();

    rpc_.call(QStringLiteral("openwallet"),
              QJsonArray{walletPath, walletPass},
              this,
              [this, walletPath](const QJsonValue&) {
                  systemLogView_->appendPlainText(QStringLiteral("[gui] opened wallet session %1").arg(walletPath));
                  setConnectionStatus(QStringLiteral("Wallet opened."));
                  refreshWalletSessionState();
                  refreshWalletRegistry();
                  walletPage_->refresh();
                  refreshSyncState();
              },
              [this](const QString& error) {
                  if (isRpcAuthError(error)) {
                      setConnectionStatus(QStringLiteral("RPC authentication failed. Check RPC user/password in Settings or cryptex.conf."), true);
                  } else {
                      setConnectionStatus(QStringLiteral("Failed to open wallet: %1").arg(error), true);
                  }
                  if (systemLogView_) {
                      systemLogView_->appendPlainText(QStringLiteral("[gui] wallet open failed: %1").arg(error));
                  }
              });
}

void MainWindow::closeWalletSession() {
    rpc_.call(QStringLiteral("closewallet"), {}, this,
        [this](const QJsonValue&) {
            systemLogView_->appendPlainText(QStringLiteral("[gui] closed wallet session"));
            setConnectionStatus(QStringLiteral("Wallet closed."));
            refreshWalletSessionState();
            refreshWalletRegistry();
            walletPage_->refresh();
            refreshSyncState();
        },
        [this](const QString& error) {
            setConnectionStatus(QStringLiteral("Failed to close wallet: %1").arg(error), true);
            if (systemLogView_) {
                systemLogView_->appendPlainText(QStringLiteral("[gui] wallet close failed: %1").arg(error));
            }
        });
}

void MainWindow::deleteWalletSession() {
    const auto walletPath = walletPathEdit_->text().trimmed();
    if (walletPath.isEmpty()) {
        setConnectionStatus(QStringLiteral("Wallet file is required to delete a wallet."), true);
        return;
    }

    rpc_.call(QStringLiteral("deletewallet"), QJsonArray{walletPath}, this,
        [this, walletPath](const QJsonValue&) {
            systemLogView_->appendPlainText(QStringLiteral("[gui] deleted wallet %1").arg(walletPath));
            setConnectionStatus(QStringLiteral("Wallet deleted."));
            walletPathEdit_->clear();
            refreshWalletSessionState();
            refreshWalletRegistry();
            walletPage_->refresh();
            refreshSyncState();
        },
        [this](const QString& error) {
            setConnectionStatus(QStringLiteral("Failed to delete wallet: %1").arg(error), true);
            if (systemLogView_) {
                systemLogView_->appendPlainText(QStringLiteral("[gui] wallet delete failed: %1").arg(error));
            }
        });
}

void MainWindow::loadSettings() {
    QSettings settings(QStringLiteral("CryptEX"), QStringLiteral("CryptEXQt"));
    rpcUrlEdit_->setText(settings.value(QStringLiteral("rpc/url"), rpcUrlEdit_->text()).toString());
    rpcUserEdit_->setText(settings.value(QStringLiteral("rpc/user"), rpcUserEdit_->text()).toString());
    rpcPasswordEdit_->setText(settings.value(QStringLiteral("rpc/password"), rpcPasswordEdit_->text()).toString());
    daemonPathEdit_->setText(settings.value(QStringLiteral("backend/executable"), daemonPathEdit_->text()).toString());
    dataDirEdit_->setText(settings.value(QStringLiteral("backend/datadir")).toString());
    const auto walletFormat = settings.value(QStringLiteral("wallet/format"), QStringLiteral("base64")).toString();
    const auto walletFormatIndex = walletFormatCombo_->findData(walletFormat);
    if (walletFormatIndex >= 0) {
        walletFormatCombo_->setCurrentIndex(walletFormatIndex);
    }
    walletNameEdit_->setText(settings.value(QStringLiteral("wallet/name")).toString());
    directPeersEdit_->setText(settings.value(QStringLiteral("network/direct_peers")).toString());
    seedPeersEdit_->setText(settings.value(QStringLiteral("network/seed_peers")).toString());
    networkCombo_->setCurrentText(settings.value(QStringLiteral("backend/network"), QStringLiteral("mainnet")).toString());
    applyAutomaticBackendDefaults();
    applyConfigBackedDefaults();
    syncWalletPathFromDataDir();
}

void MainWindow::saveSettings() {
    QSettings settings(QStringLiteral("CryptEX"), QStringLiteral("CryptEXQt"));
    settings.setValue(QStringLiteral("rpc/url"), rpcUrlEdit_->text().trimmed());
    settings.setValue(QStringLiteral("rpc/user"), rpcUserEdit_->text().trimmed());
    settings.setValue(QStringLiteral("rpc/password"), rpcPasswordEdit_->text());
    settings.setValue(QStringLiteral("backend/executable"), daemonPathEdit_->text().trimmed());
    settings.setValue(QStringLiteral("backend/datadir"), dataDirEdit_->text().trimmed());
    settings.setValue(QStringLiteral("wallet/format"), walletFormatCombo_->currentData().toString());
    settings.setValue(QStringLiteral("wallet/name"), walletNameEdit_->text().trimmed());
    settings.setValue(QStringLiteral("backend/network"), networkCombo_->currentText());
    settings.setValue(QStringLiteral("network/direct_peers"), directPeersEdit_->text().trimmed());
    settings.setValue(QStringLiteral("network/seed_peers"), seedPeersEdit_->text().trimmed());
    setConnectionStatus(QStringLiteral("GUI settings saved."));
}

void MainWindow::applyRpcSettings() {
    RpcClient::Settings settings;
    settings.url = QUrl(rpcUrlEdit_->text().trimmed());
    settings.username = rpcUserEdit_->text().trimmed();
    settings.password = rpcPasswordEdit_->text();
    rpc_.setSettings(settings);
    setConnectionStatus(QStringLiteral("RPC settings applied."));
    if (systemLogView_) {
        systemLogView_->appendPlainText(QStringLiteral("[gui] Applied RPC settings for %1 as %2")
            .arg(settings.url.toString(), settings.username.isEmpty() ? QStringLiteral("<anonymous>") : settings.username));
    }
}

void MainWindow::bootstrapBackendAndRefresh(int retries, int generation) {
    if (generation < 0) {
        generation = backendBootstrapGeneration_;
    }
    rpc_.call(QStringLiteral("getnetworkinfo"), {}, this,
        [this, generation](const QJsonValue&) {
            if (generation != backendBootstrapGeneration_) {
                return;
            }
            backendBootstrapInProgress_ = false;
            setBackendState(QStringLiteral("Connected"));
            setConnectionStatus(QStringLiteral("Connected to cryptexd backend."));
            systemLogView_->appendPlainText(QStringLiteral("[gui] Connected to backend RPC"));
            refreshSyncState();
            refreshAll();
        },
        [this, retries, generation](const QString& error) {
            if (generation != backendBootstrapGeneration_) {
                return;
            }
            const auto daemonPath = daemonPathEdit_->text().trimmed();
            const bool authError = isRpcAuthError(error);
            const bool retryableStartupError = isRetryableRpcStartupError(error);

            if (!authError && !daemon_.isRunning() && !daemonPath.isEmpty() && retryableStartupError) {
                backendBootstrapInProgress_ = true;
                setBackendState(QStringLiteral("Starting backend..."));
                refreshSyncState();
                startBackend();
                return;
            }

            if (backendBootstrapInProgress_ && retries > 0) {
                setBackendState(QStringLiteral("Waiting for RPC..."));
                setConnectionStatus(QStringLiteral("Waiting for cryptexd backend to accept RPC..."));
                refreshSyncState();
                QTimer::singleShot(1000, this, [this, retries, generation]() {
                    if (generation == backendBootstrapGeneration_) {
                        bootstrapBackendAndRefresh(retries - 1, generation);
                    }
                });
                return;
            }

            backendBootstrapInProgress_ = false;
            setBackendState(QStringLiteral("Backend unavailable"), true);
            if (authError) {
                setConnectionStatus(QStringLiteral("RPC rejected the connection. Check the local RPC user/password in Settings or cryptex.conf."), true);
                systemLogView_->appendPlainText(QStringLiteral("[gui] RPC auth rejected: %1").arg(error));
            } else {
                setConnectionStatus(error, true);
                systemLogView_->appendPlainText(QStringLiteral("[gui] RPC connection failed: %1").arg(error));
            }
            refreshSyncState();
        });
}

void MainWindow::setBackendState(const QString& text, bool error) {
    daemonStatusLabel_->setText(QStringLiteral("Node: %1").arg(text));
    if (error) {
        daemonStatusLabel_->setStyleSheet(QStringLiteral("color:#d36b6b; font-weight:600;"));
    } else if (text.contains(QStringLiteral("Waiting"), Qt::CaseInsensitive) ||
               text.contains(QStringLiteral("Starting"), Qt::CaseInsensitive)) {
        daemonStatusLabel_->setStyleSheet(QStringLiteral("color:#e1d49a; font-weight:600;"));
    } else {
        daemonStatusLabel_->setStyleSheet(QStringLiteral("color:#8ed0a2; font-weight:600;"));
    }
}

void MainWindow::openNodeWindow(const QString& section) {
    if (!nodeWindow_) {
        return;
    }
    nodeWindow_->showSection(section);
    refreshVisibleNodeSection();
}

void MainWindow::refreshNodeInformation() {
    if (!nodeInfoPage_) {
        return;
    }

    nodeRpcTargetValue_->setText(rpcUrlEdit_->text().trimmed());
    nodeDataDirValue_->setText(dataDirEdit_->text().trimmed());
    nodePeerModeValue_->setText(parsePeerEntryList(directPeersEdit_->text()).isEmpty() &&
                                parsePeerEntryList(seedPeersEdit_->text()).isEmpty()
        ? QStringLiteral("Automatic global discovery")
        : QStringLiteral("Manual peers and/or seeds configured"));

    rpc_.call(QStringLiteral("getnetworkinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            nodeClientVersionValue_->setText(obj.value(QStringLiteral("subversion")).toString(QStringLiteral("/CryptEX Qt/")));
            nodeNetworkValue_->setText(obj.value(QStringLiteral("network")).toString(networkCombo_->currentText()));
            connectedPeerCount_ = obj.value(QStringLiteral("connections")).toInteger();
            networkActive_ = obj.value(QStringLiteral("networkactive")).toBool(true);
            nodeConnectionValue_->setText(QStringLiteral("%1 connected / %2 validated / %3 known")
                .arg(obj.value(QStringLiteral("connections")).toInteger())
                .arg(obj.value(QStringLiteral("validatedpeers")).toInteger())
                .arg(obj.value(QStringLiteral("knownpeers")).toInteger()));
            nodeApprovalValue_->setText(obj.value(QStringLiteral("chain_approved")).toBool(false)
                ? QStringLiteral("Approved")
                : QStringLiteral("Locked until sync approval"));
            updateStatusIcons();
        },
        [this](const QString& error) {
            nodeClientVersionValue_->setText(QStringLiteral("-"));
            nodeNetworkValue_->setText(QStringLiteral("-"));
            nodeConnectionValue_->setText(QStringLiteral("Unavailable"));
            nodeApprovalValue_->setText(QStringLiteral("Unavailable"));
            connectedPeerCount_ = 0;
            updateStatusIcons();
            if (systemLogView_) {
                systemLogView_->appendPlainText(QStringLiteral("[gui] node info refresh failed: %1").arg(error));
            }
        });

    rpc_.call(QStringLiteral("getblockchaininfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            const auto blocks = obj.value(QStringLiteral("blocks")).toInteger();
            const auto headers = obj.value(QStringLiteral("headers")).toInteger();
            nodeHeightValue_->setText(QStringLiteral("%1 blocks / %2 headers").arg(blocks).arg(headers));
            nodeSyncValue_->setText(obj.value(QStringLiteral("initialblockdownload")).toBool(false)
                ? QStringLiteral("%1% synced, %2 blocks left")
                      .arg(QString::number(obj.value(QStringLiteral("verificationprogress")).toDouble(0.0) * 100.0, 'f', 2))
                      .arg(obj.value(QStringLiteral("blocksleft")).toInteger())
                : QStringLiteral("Synchronized"));
        },
        [this](const QString&) {
            nodeHeightValue_->setText(QStringLiteral("Unavailable"));
            nodeSyncValue_->setText(QStringLiteral("Unavailable"));
        });

    rpc_.call(QStringLiteral("getmempoolinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            nodeMempoolValue_->setText(QStringLiteral("%1 tx / %2 bytes")
                .arg(obj.value(QStringLiteral("size")).toInteger())
                .arg(obj.value(QStringLiteral("bytes")).toInteger()));
        },
        [this](const QString&) {
            nodeMempoolValue_->setText(QStringLiteral("Unavailable"));
        });
}

void MainWindow::refreshAll() {
    if (refreshWaveInFlight_) {
        refreshWaveQueued_ = true;
        return;
    }
    refreshWaveInFlight_ = true;
    if (refreshCooldownTimer_) {
        refreshCooldownTimer_->start();
    }

    refreshSyncState();
    if (backendBootstrapInProgress_) return;
    refreshWalletSessionState();
    reconcilePendingMinedBlocks();
    refreshCurrentMainTab();
    refreshVisibleNodeSection();
}

void MainWindow::refreshCurrentMainTab() {
    if (!tabs_) {
        return;
    }

    switch (tabs_->currentIndex()) {
    case 0:
        dashboardPage_->refresh();
        break;
    case 1:
        sendPage_->refresh();
        break;
    case 2:
        receivePage_->refresh();
        break;
    case 3:
        transactionsPage_->refresh();
        break;
    default:
        break;
    }
}

void MainWindow::refreshVisibleNodeSection() {
    if (!nodeWindow_ || !nodeWindow_->isVisible()) {
        return;
    }

    const auto section = nodeWindow_->currentSection();
    if (section == QStringLiteral("information")) {
        refreshNodeInformation();
        refreshCheckpointManager();
    } else if (section == QStringLiteral("wallets")) {
        refreshWalletRegistry();
    } else if (section == QStringLiteral("wallet")) {
        walletPage_->refresh();
    } else if (section == QStringLiteral("chat")) {
        chatPage_->refresh();
    } else if (section == QStringLiteral("mining")) {
        miningPage_->refresh();
    } else if (section == QStringLiteral("network")) {
        networkGraphPage_->refresh();
    }
}

void MainWindow::refreshCheckpointManager() {
    rpc_.call(QStringLiteral("getcheckpointinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            const bool present = obj.value(QStringLiteral("present")).toBool(false);
            const bool pinned = obj.value(QStringLiteral("pinned")).toBool(false);
            checkpointModeValue_->setText(!present ? QStringLiteral("None")
                                                   : (pinned ? QStringLiteral("Pinned") : QStringLiteral("Automatic")));
            checkpointHeightValue_->setText(present ? QString::number(obj.value(QStringLiteral("height")).toInteger())
                                                    : QStringLiteral("-"));
            checkpointHashValue_->setText(present ? obj.value(QStringLiteral("hash")).toString()
                                                  : QStringLiteral("-"));
            checkpointGuardValue_->setText(QStringLiteral("max depth %1%2")
                .arg(obj.value(QStringLiteral("max_reorg_depth")).toInteger())
                .arg(obj.value(QStringLiteral("allow_deep_reorg")).toBool(false)
                    ? QStringLiteral(" (deep reorg env override active)")
                    : QString()));
            checkpointClearButton_->setEnabled(pinned);
        },
        [this](const QString&) {
            checkpointModeValue_->setText(QStringLiteral("Unavailable"));
            checkpointHeightValue_->setText(QStringLiteral("-"));
            checkpointHashValue_->setText(QStringLiteral("-"));
            checkpointGuardValue_->setText(QStringLiteral("-"));
            checkpointClearButton_->setEnabled(false);
        });

    rpc_.call(QStringLiteral("getportmappinginfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            const bool active = obj.value(QStringLiteral("active")).toBool(false);
            if (active) {
                portMappingValue_->setText(QStringLiteral("%1 %2")
                    .arg(obj.value(QStringLiteral("protocol")).toString())
                    .arg(obj.value(QStringLiteral("external_endpoint")).toString()));
            } else {
                portMappingValue_->setText(obj.value(QStringLiteral("message")).toString(QStringLiteral("Inactive")));
            }
        },
        [this](const QString&) {
            portMappingValue_->setText(QStringLiteral("Unavailable"));
        });
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
                    [this, height, submitNext, path](const QJsonValue& response) {
                        const auto status = response.toString();
                        systemLogView_->appendPlainText(QStringLiteral("[gui] reconciled mined block height %1 -> %2").arg(height).arg(status));
                        // FIX: Remove file after successful submission
                        if (status == QStringLiteral("accepted") || status == QStringLiteral("duplicate")) {
                            QFile::remove(path);
                        }
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
    systemLogView_->appendPlainText(QStringLiteral("[gui] Start Backend requested"));
    ++backendBootstrapGeneration_;
    const int bootstrapGeneration = backendBootstrapGeneration_;
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
    persistLocalRpcConfig();
    saveSettings();
    rpc_.call(QStringLiteral("getnetworkinfo"), {}, this,
        [this, bootstrapGeneration](const QJsonValue&) {
            if (bootstrapGeneration != backendBootstrapGeneration_) {
                return;
            }
            backendBootstrapInProgress_ = false;
            setBackendState(QStringLiteral("Connected"));
            setConnectionStatus(QStringLiteral("Existing cryptexd backend is already running. Attached without starting a second node."));
            systemLogView_->appendPlainText(QStringLiteral("[gui] Existing backend already running; attached without starting a second process"));
            if (!parsePeerEntryList(directPeersEdit_->text()).isEmpty() || !parsePeerEntryList(seedPeersEdit_->text()).isEmpty()) {
                systemLogView_->appendPlainText(QStringLiteral("[gui] Direct peer / seed changes only apply on backend launch. Stop and start the backend to apply them."));
            }
            refreshSyncState();
            refreshAll();
        },
        [this, bootstrapGeneration](const QString& error) {
            if (bootstrapGeneration != backendBootstrapGeneration_) {
                return;
            }
            if (isRpcAuthError(error)) {
                backendBootstrapInProgress_ = false;
                setBackendState(QStringLiteral("RPC auth rejected"), true);
                setConnectionStatus(QStringLiteral("A backend is likely already running, but the RPC credentials do not match. Check Settings or cryptex.conf."), true);
                systemLogView_->appendPlainText(QStringLiteral("[gui] RPC auth rejected while probing existing backend: %1").arg(error));
                refreshSyncState();
                return;
            }
            launchBackendProcess();
        });
}

void MainWindow::launchBackendProcess() {
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
    config.connectTargets = parsePeerEntryList(directPeersEdit_->text());
    config.seedTargets = parsePeerEntryList(seedPeersEdit_->text());
    config.debug = true;
    if (!config.connectTargets.isEmpty()) {
        systemLogView_->appendPlainText(QStringLiteral("[gui] Direct peer targets: %1").arg(config.connectTargets.join(QStringLiteral(", "))));
    }
    if (!config.seedTargets.isEmpty()) {
        systemLogView_->appendPlainText(QStringLiteral("[gui] Seed targets: %1").arg(config.seedTargets.join(QStringLiteral(", "))));
    } else if (config.connectTargets.isEmpty()) {
        systemLogView_->appendPlainText(QStringLiteral("[gui] No manual peers configured; using built-in automatic global peer discovery."));
    }
    daemon_.startNode(config);
    backendBootstrapInProgress_ = true;
    syncOverlayDismissed_ = false;
    syncOverlayPinned_ = true;
    connectedPeerCount_ = 0;
    networkActive_ = true;
    networkSyncing_ = true;
    setBackendState(QStringLiteral("Starting backend..."));
    setConnectionStatus(QStringLiteral("Launching cryptexd backend..."));
    updateSyncStatusBar(QStringLiteral("Synchronizing with network..."), true);
    setStartupOverlayVisible(true);
    refreshSyncState();
    const int bootstrapGeneration = backendBootstrapGeneration_;
    QTimer::singleShot(1500, this, [this, bootstrapGeneration]() {
        if (bootstrapGeneration == backendBootstrapGeneration_) {
            bootstrapBackendAndRefresh(20, bootstrapGeneration);
        }
    });
}

void MainWindow::handleBackendPortConflict() {
    backendBootstrapInProgress_ = false;
    setBackendState(QStringLiteral("Existing backend detected"));
    setConnectionStatus(QStringLiteral("Ports are already in use by another cryptexd instance. Trying to attach to the existing backend."));
    const int bootstrapGeneration = backendBootstrapGeneration_;
    QTimer::singleShot(250, this, [this, bootstrapGeneration]() {
        if (bootstrapGeneration == backendBootstrapGeneration_) {
            bootstrapBackendAndRefresh(3, bootstrapGeneration);
        }
    });
}

void MainWindow::stopBackend() {
    ++backendBootstrapGeneration_;
    daemon_.stopNode();
    backendBootstrapInProgress_ = false;
    syncOverlayDismissed_ = false;
    syncOverlayPinned_ = false;
    connectedPeerCount_ = 0;
    networkActive_ = false;
    networkSyncing_ = false;
    setBackendState(QStringLiteral("Backend stopped"));
    setConnectionStatus(QStringLiteral("Stopping backend..."));
    setStartupProgressBusy(false);
    updateSyncStatusBar(QStringLiteral("Node stopped"), false, 0.0);
    setStartupOverlayVisible(false);
    updateStatusIcons();
}

void MainWindow::setConnectionStatus(const QString& text, bool error) {
    const auto message = error ? QStringLiteral("Error: %1").arg(text) : text;
    statusBar()->showMessage(message, error ? 8000 : 4000);
}
MainWindow::~MainWindow() {
    if (daemon_.isRunning()) {
        stopBackend();
    }
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (daemon_.isRunning()) {
        stopBackend();
    }
    event->accept();
}

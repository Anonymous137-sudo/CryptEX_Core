#include "MiningPage.hpp"
#include "rpc/RpcClient.hpp"

#include <QCheckBox>
#include <QDir>
#include <QFormLayout>
#include <QGroupBox>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {
QLabel* makeValueLabel() {
    auto* label = new QLabel(QStringLiteral("-"));
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    label->setWordWrap(true);
    return label;
}
}

MiningPage::MiningPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    auto* title = new QLabel(QStringLiteral("Mining Control"));
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* summaryBox = new QGroupBox(QStringLiteral("Chain Status"), this);
    auto* summaryLayout = new QFormLayout(summaryBox);
    blocksValue_ = makeValueLabel();
    difficultyValue_ = makeValueLabel();
    hashrateValue_ = makeValueLabel();
    peerValue_ = makeValueLabel();
    minerStateValue_ = makeValueLabel();
    statusValue_ = makeValueLabel();
    summaryLayout->addRow(QStringLiteral("Blocks"), blocksValue_);
    summaryLayout->addRow(QStringLiteral("Difficulty"), difficultyValue_);
    summaryLayout->addRow(QStringLiteral("Estimated Network Hashrate"), hashrateValue_);
    summaryLayout->addRow(QStringLiteral("Connections"), peerValue_);
    summaryLayout->addRow(QStringLiteral("Miner State"), minerStateValue_);
    summaryLayout->addRow(QStringLiteral("Status"), statusValue_);
    root->addWidget(summaryBox);

    auto* configBox = new QGroupBox(QStringLiteral("Miner Session"), this);
    auto* configLayout = new QFormLayout(configBox);
    addressEdit_ = new QLineEdit(this);
    connectEdit_ = new QLineEdit(this);
    minerDataDirEdit_ = new QLineEdit(this);
    cyclesEdit_ = new QLineEdit(QStringLiteral("0"), this);
    blockCyclesEdit_ = new QLineEdit(QStringLiteral("1"), this);
    syncWaitEdit_ = new QLineEdit(QStringLiteral("0"), this);
    threadSpin_ = new QSpinBox(this);
    threadSpin_->setRange(1, 256);
    threadSpin_->setValue(1);
    debugCheck_ = new QCheckBox(QStringLiteral("Enable detailed miner output"), this);
    usePrimaryButton_ = new QPushButton(QStringLiteral("Use Wallet Primary Address"), this);
    startButton_ = new QPushButton(QStringLiteral("Start Mining"), this);
    stopButton_ = new QPushButton(QStringLiteral("Stop Mining"), this);
    refreshButton_ = new QPushButton(QStringLiteral("Refresh"), this);

    addressEdit_->setPlaceholderText(QStringLiteral("Base64 reward address"));
    connectEdit_->setPlaceholderText(QStringLiteral("Defaults to the local node, for example 127.0.0.1:9333"));
    minerDataDirEdit_->setPlaceholderText(QStringLiteral("Defaults to a dedicated miner subdirectory"));
    cyclesEdit_->setPlaceholderText(QStringLiteral("0 = infinite nonce loop"));
    blockCyclesEdit_->setPlaceholderText(QStringLiteral("0 = mine blocks continuously"));
    syncWaitEdit_->setPlaceholderText(QStringLiteral("0 = wait until synced"));

    configLayout->addRow(QStringLiteral("Reward Address"), addressEdit_);
    configLayout->addRow(QString(), usePrimaryButton_);
    configLayout->addRow(QStringLiteral("Peer / Seed Target"), connectEdit_);
    configLayout->addRow(QStringLiteral("Miner Data Dir"), minerDataDirEdit_);
    configLayout->addRow(QStringLiteral("Nonce Cycles"), cyclesEdit_);
    configLayout->addRow(QStringLiteral("Block Cycles"), blockCyclesEdit_);
    configLayout->addRow(QStringLiteral("Threads"), threadSpin_);
    configLayout->addRow(QStringLiteral("Sync Wait (ms)"), syncWaitEdit_);
    configLayout->addRow(QStringLiteral("Debug"), debugCheck_);

    auto* actionRow = new QWidget(this);
    auto* actionLayout = new QHBoxLayout(actionRow);
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->addWidget(startButton_);
    actionLayout->addWidget(stopButton_);
    actionLayout->addWidget(refreshButton_);
    configLayout->addRow(QString(), actionRow);
    root->addWidget(configBox);

    auto* note = new QLabel(QStringLiteral("The GUI miner uses its own datadir by default. If you leave the peer target blank it will mine against the local node, and found blocks are submitted back into the backend so your wallet and dashboard stay in sync. Live miner logs appear in the separate Miner Output tab."));
    note->setWordWrap(true);
    root->addWidget(note);
    root->addStretch(1);

    connect(usePrimaryButton_, &QPushButton::clicked, this, [this]() { usePrimaryAddress(); });
    connect(startButton_, &QPushButton::clicked, this, [this]() { startMining(); });
    connect(stopButton_, &QPushButton::clicked, this, [this]() { stopMining(); });
    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });

    minerStateValue_->setText(QStringLiteral("Stopped"));
    stopButton_->setEnabled(false);
}

void MiningPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void MiningPage::setMinerController(MinerController* controller) {
    miner_ = controller;
    if (!miner_) return;

    connect(miner_, &MinerController::stateChanged, this, [this](bool running) {
        minerStateValue_->setText(running ? QStringLiteral("Running") : QStringLiteral("Stopped"));
        startButton_->setEnabled(!running);
        stopButton_->setEnabled(running);
        setStatus(running ? QStringLiteral("Miner process running.") : QStringLiteral("Miner process stopped."));
    });
}

void MiningPage::setBaseLaunchConfigProvider(std::function<MinerController::LaunchConfig()> provider) {
    baseConfigProvider_ = std::move(provider);
}

QString MiningPage::formatHashrate(double hps) {
    if (hps >= 1e9) return QString::number(hps / 1e9, 'f', 2) + QStringLiteral(" GH/s");
    if (hps >= 1e6) return QString::number(hps / 1e6, 'f', 2) + QStringLiteral(" MH/s");
    if (hps >= 1e3) return QString::number(hps / 1e3, 'f', 2) + QStringLiteral(" kH/s");
    return QString::number(hps, 'f', 2) + QStringLiteral(" H/s");
}

QString MiningPage::defaultPeerForNetwork(const QString& network) {
    if (network == QStringLiteral("testnet")) return QStringLiteral("127.0.0.1:19333");
    if (network == QStringLiteral("regtest")) return QStringLiteral("127.0.0.1:19444");
    return QStringLiteral("127.0.0.1:9333");
}

void MiningPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#a61b1b;") : QString());
}

void MiningPage::usePrimaryAddress() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    rpc_->call(QStringLiteral("getwalletinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto address = result.toObject().value(QStringLiteral("primaryaddress")).toString();
            if (address.isEmpty()) {
                setStatus(QStringLiteral("Wallet returned an empty primary address."), true);
                return;
            }
            addressEdit_->setText(address);
            setStatus(QStringLiteral("Loaded primary wallet address."));
        },
        [this](const QString& error) { setStatus(error, true); });
}

void MiningPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    setStatus(QStringLiteral("Refreshing mining status..."));
    rpc_->call(QStringLiteral("getmininginfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            blocksValue_->setText(QString::number(obj.value(QStringLiteral("blocks")).toInteger()));
            difficultyValue_->setText(QString::number(obj.value(QStringLiteral("difficulty")).toDouble(), 'f', 6));
            hashrateValue_->setText(QStringLiteral("%1 (from current difficulty)")
                .arg(formatHashrate(obj.value(QStringLiteral("networkhashps")).toDouble())));
        },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("getnetworkinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            peerValue_->setText(QStringLiteral("%1 live / %2 known")
                .arg(obj.value(QStringLiteral("connections")).toInteger())
                .arg(obj.value(QStringLiteral("knownpeers")).toInteger()));
            setStatus(QStringLiteral("Mining dashboard ready."));
        },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("getwalletinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            if (addressEdit_->text().trimmed().isEmpty()) {
                addressEdit_->setText(obj.value(QStringLiteral("primaryaddress")).toString());
            }
        },
        [this](const QString&) {});
}

void MiningPage::startMining() {
    if (!miner_) {
        setStatus(QStringLiteral("Miner controller not configured."), true);
        return;
    }
    if (!baseConfigProvider_) {
        setStatus(QStringLiteral("Backend launch context is unavailable."), true);
        return;
    }

    bool cyclesOk = false;
    bool blockCyclesOk = false;
    bool syncWaitOk = false;
    const quint64 cycles = cyclesEdit_->text().trimmed().isEmpty() ? 0 : cyclesEdit_->text().trimmed().toULongLong(&cyclesOk);
    const quint64 blockCycles = blockCyclesEdit_->text().trimmed().isEmpty() ? 1 : blockCyclesEdit_->text().trimmed().toULongLong(&blockCyclesOk);
    const quint64 syncWait = syncWaitEdit_->text().trimmed().isEmpty() ? 0 : syncWaitEdit_->text().trimmed().toULongLong(&syncWaitOk);
    if ((!cyclesEdit_->text().trimmed().isEmpty() && !cyclesOk) ||
        (!blockCyclesEdit_->text().trimmed().isEmpty() && !blockCyclesOk) ||
        (!syncWaitEdit_->text().trimmed().isEmpty() && !syncWaitOk)) {
        setStatus(QStringLiteral("Nonce cycles, block cycles, and sync wait must be unsigned integers."), true);
        return;
    }

    auto config = baseConfigProvider_();
    config.rewardAddress = addressEdit_->text().trimmed();
    config.connectEndpoint = connectEdit_->text().trimmed();
    config.cycles = cycles;
    config.blockCycles = blockCycles;
    config.threads = static_cast<quint32>(threadSpin_->value());
    config.syncWaitMs = syncWait;
    config.debug = debugCheck_->isChecked();

    if (config.rewardAddress.isEmpty()) {
        setStatus(QStringLiteral("Reward address is required."), true);
        return;
    }

    if (config.connectEndpoint.isEmpty()) {
        config.connectEndpoint = defaultPeerForNetwork(config.network);
        connectEdit_->setPlaceholderText(config.connectEndpoint);
    }

    if (minerDataDirEdit_->text().trimmed().isEmpty()) {
        QString baseDir = config.dataDir.trimmed();
        if (baseDir.isEmpty()) {
            setStatus(QStringLiteral("Set a backend datadir before starting the GUI miner."), true);
            return;
        }
        config.dataDir = QDir(baseDir).filePath(QStringLiteral("gui-miner"));
    } else {
        config.dataDir = minerDataDirEdit_->text().trimmed();
    }

    miner_->startMining(config);
    setStatus(QStringLiteral("Launching miner process..."));
}

void MiningPage::stopMining() {
    if (!miner_) {
        setStatus(QStringLiteral("Miner controller not configured."), true);
        return;
    }
    miner_->stopMining();
    setStatus(QStringLiteral("Stopping miner process..."));
}

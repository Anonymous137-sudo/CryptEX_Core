#pragma once

#include <QMainWindow>
#include "rpc/RpcClient.hpp"
#include "app/DaemonController.hpp"
#include "app/MinerController.hpp"

class DashboardPage;
class NetworkGraphPage;
class WalletPage;
class ChatPage;
class MiningPage;
class RpcConsolePage;
class TerminalPage;
class QComboBox;
class QLineEdit;
class QTextEdit;
class QTabWidget;
class QLabel;
class QTimer;
class QPlainTextEdit;
class QWidget;
class QProgressBar;
class QPushButton;
class QResizeEvent;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override = default;

protected:
    void resizeEvent(QResizeEvent* event) override;

private:
    void buildUi();
    void loadSettings();
    void saveSettings();
    void applyRpcSettings();
    void applyAutomaticBackendDefaults();
    void applyConfigBackedDefaults();
    void syncWalletPathFromDataDir();
    QString defaultDataDirForNetwork(const QString& network) const;
    QString defaultWalletPathForDataDir(const QString& dataDir) const;
    QString defaultConfigPathForDataDir(const QString& dataDir) const;
    QString defaultMinerDataDirForDataDir(const QString& dataDir) const;
    QUrl defaultRpcUrlForNetwork(const QString& network) const;
    void bootstrapBackendAndRefresh(int retries = 8);
    void setBackendState(const QString& text, bool error = false);
    void refreshAll();
    void refreshSyncState();
    void updateSyncOverlay(const QJsonObject& blockchainInfo);
    void setStartupOverlayVisible(bool visible);
    void layoutStartupOverlay();
    QString formatSyncEta(double hours_remaining) const;
    QString formatSyncTimestamp(qint64 epoch_seconds) const;
    void reconcilePendingMinedBlocks();
    void submitMinedBlockToBackend(const QString& blockHex);
    void startBackend();
    void stopBackend();
    QString guessedDaemonPath() const;
    void setConnectionStatus(const QString& text, bool error = false);

    RpcClient rpc_;
    DaemonController daemon_;
    MinerController miner_;

    QLineEdit* rpcUrlEdit_{nullptr};
    QLineEdit* rpcUserEdit_{nullptr};
    QLineEdit* rpcPasswordEdit_{nullptr};
    QLineEdit* daemonPathEdit_{nullptr};
    QLineEdit* dataDirEdit_{nullptr};
    QLineEdit* walletPathEdit_{nullptr};
    QLineEdit* walletPassEdit_{nullptr};
    QComboBox* networkCombo_{nullptr};
    QLabel* daemonStatusLabel_{nullptr};
    QTabWidget* tabs_{nullptr};
    QWidget* settingsPage_{nullptr};
    DashboardPage* dashboardPage_{nullptr};
    NetworkGraphPage* networkGraphPage_{nullptr};
    WalletPage* walletPage_{nullptr};
    ChatPage* chatPage_{nullptr};
    MiningPage* miningPage_{nullptr};
    RpcConsolePage* rpcConsolePage_{nullptr};
    TerminalPage* terminalPage_{nullptr};
    QPlainTextEdit* systemLogView_{nullptr};
    QPlainTextEdit* minerOutputView_{nullptr};
    QWidget* startupOverlay_{nullptr};
    QWidget* startupPanel_{nullptr};
    QLabel* startupIntroLabel_{nullptr};
    QLabel* startupSummaryLabel_{nullptr};
    QLabel* startupBlocksLeftLabel_{nullptr};
    QLabel* startupLastBlockLabel_{nullptr};
    QLabel* startupProgressLabel_{nullptr};
    QLabel* startupRateLabel_{nullptr};
    QLabel* startupEtaLabel_{nullptr};
    QLabel* startupStateLabel_{nullptr};
    QProgressBar* startupProgressBar_{nullptr};
    QPushButton* startupHideButton_{nullptr};
    QPushButton* syncDetailsButton_{nullptr};
    QTimer* refreshTimer_{nullptr};
    bool backendBootstrapInProgress_{false};
    QString autoDaemonPath_;
    QString autoDataDir_;
    QString autoWalletPath_;
    QString autoRpcUrl_;
    QString autoRpcUser_;
    QString autoRpcPassword_;
    bool reconcileInProgress_{false};
    bool syncOverlayDismissed_{false};
    bool syncOverlayPinned_{false};
    double lastSyncProgress_{-1.0};
    qint64 lastSyncSampleMs_{0};
};

#pragma once

#include <QWidget>
#include <functional>

#include "app/MinerController.hpp"

class QLabel;
class QLineEdit;
class QSpinBox;
class QPushButton;
class QCheckBox;
class RpcClient;

class MiningPage : public QWidget {
    Q_OBJECT
public:
    explicit MiningPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void setMinerController(MinerController* controller);
    void setBaseLaunchConfigProvider(std::function<MinerController::LaunchConfig()> provider);
    void refresh();

private:
    static QString formatHashrate(double hps);
    static QString defaultPeerForNetwork(const QString& network);
    void setStatus(const QString& text, bool error = false);
    void startMining();
    void stopMining();
    void usePrimaryAddress();

    RpcClient* rpc_{nullptr};
    MinerController* miner_{nullptr};
    std::function<MinerController::LaunchConfig()> baseConfigProvider_;

    QLabel* blocksValue_{nullptr};
    QLabel* difficultyValue_{nullptr};
    QLabel* hashrateValue_{nullptr};
    QLabel* peerValue_{nullptr};
    QLabel* minerStateValue_{nullptr};
    QLabel* statusValue_{nullptr};
    QLineEdit* addressEdit_{nullptr};
    QLineEdit* connectEdit_{nullptr};
    QLineEdit* minerDataDirEdit_{nullptr};
    QLineEdit* cyclesEdit_{nullptr};
    QLineEdit* blockCyclesEdit_{nullptr};
    QLineEdit* syncWaitEdit_{nullptr};
    QSpinBox* threadSpin_{nullptr};
    QCheckBox* debugCheck_{nullptr};
    QPushButton* usePrimaryButton_{nullptr};
    QPushButton* startButton_{nullptr};
    QPushButton* stopButton_{nullptr};
    QPushButton* refreshButton_{nullptr};
};

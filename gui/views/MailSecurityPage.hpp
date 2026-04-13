#pragma once

#include <QWidget>

class QLabel;
class QCheckBox;
class QLineEdit;
class QSpinBox;
class QPushButton;
class RpcClient;

class MailSecurityPage : public QWidget {
    Q_OBJECT
public:
    explicit MailSecurityPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    void setStatus(const QString& text, bool error = false);
    void saveProxy();
    void saveTwoFactor();
    void verifyTwoFactor();

    RpcClient* rpc_{nullptr};
    QLabel* statusValue_{nullptr};
    QLabel* distributedStoreValue_{nullptr};
    QCheckBox* proxyEnabledCheck_{nullptr};
    QLineEdit* proxyHostEdit_{nullptr};
    QSpinBox* proxyPortSpin_{nullptr};
    QCheckBox* proxyRemoteDnsCheck_{nullptr};
    QPushButton* proxyReloadButton_{nullptr};
    QPushButton* proxySaveButton_{nullptr};
    QCheckBox* twoFactorEnabledCheck_{nullptr};
    QLineEdit* issuerEdit_{nullptr};
    QLineEdit* secretEdit_{nullptr};
    QLineEdit* otpAuthUriEdit_{nullptr};
    QLineEdit* verifyCodeEdit_{nullptr};
    QPushButton* regenerateButton_{nullptr};
    QPushButton* verifyButton_{nullptr};
    QPushButton* saveTwoFactorButton_{nullptr};
    QSpinBox* ttlHoursSpin_{nullptr};
    QSpinBox* replicaTargetSpin_{nullptr};
    QSpinBox* maxStoreItemsSpin_{nullptr};
    QCheckBox* pruneImportedCheck_{nullptr};
    QCheckBox* pruneExpiredCheck_{nullptr};
    QCheckBox* proofOfStorageCheck_{nullptr};
    QSpinBox* challengeIntervalSpin_{nullptr};
    QLineEdit* minimumBondEdit_{nullptr};
    QSpinBox* requiredVerifiedReplicasSpin_{nullptr};
    QCheckBox* slashOnFailedProofCheck_{nullptr};
    QSpinBox* slashPenaltySpin_{nullptr};
    QCheckBox* natAssistCheck_{nullptr};
    QCheckBox* relayFallbackCheck_{nullptr};
    QLineEdit* relayPeersEdit_{nullptr};
    QLineEdit* stunServersEdit_{nullptr};
    QSpinBox* stunTimeoutSpin_{nullptr};
    QPushButton* savePolicyButton_{nullptr};
};

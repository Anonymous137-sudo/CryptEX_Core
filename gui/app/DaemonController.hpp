#pragma once

#include <QObject>
#include <QProcess>
#include <QTimer>

class DaemonController : public QObject {
    Q_OBJECT
public:
    struct LaunchConfig {
        QString executablePath;
        QString network;
        QString dataDir;
        QString rpcBind;
        int rpcPort{9332};
        bool rpcTls{false};
        QString rpcTlsCertPath;
        QString rpcTlsKeyPath;
        QString rpcUser;
        QString rpcPassword;
        QString walletPath;
        QString walletPassword;
        QStringList connectTargets;
        QStringList seedTargets;
        bool debug{false};
    };

    explicit DaemonController(QObject* parent = nullptr);
    ~DaemonController(); // Added

    bool isRunning() const;
    void startNode(const LaunchConfig& config);
    void stopNode(bool synchronous = false);

signals:
    void stateChanged(bool running);
    void outputLine(const QString& line);
    void errorLine(const QString& line);

private:
    void flushBufferedLines(QString& buffer, bool error);

    QProcess process_;
    QTimer killFallbackTimer_;
    QString stdoutBuffer_;
    QString stderrBuffer_;
    bool stopRequested_{false};
};

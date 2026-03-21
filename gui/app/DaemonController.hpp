#pragma once

#include <QObject>
#include <QProcess>

class DaemonController : public QObject {
    Q_OBJECT
public:
    struct LaunchConfig {
        QString executablePath;
        QString network;
        QString dataDir;
        QString rpcBind;
        int rpcPort{9332};
        QString rpcUser;
        QString rpcPassword;
        QString walletPath;
        QString walletPassword;
        bool debug{false};
    };

    explicit DaemonController(QObject* parent = nullptr);

    bool isRunning() const;
    void startNode(const LaunchConfig& config);
    void stopNode();

signals:
    void stateChanged(bool running);
    void outputLine(const QString& line);
    void errorLine(const QString& line);

private:
    void flushBufferedLines(QString& buffer, bool error);

    QProcess process_;
    QString stdoutBuffer_;
    QString stderrBuffer_;
};

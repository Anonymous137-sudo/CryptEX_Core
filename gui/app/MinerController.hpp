#pragma once

#include <QObject>
#include <QProcess>

class MinerController : public QObject {
    Q_OBJECT
public:
    struct LaunchConfig {
        QString executablePath;
        QString network;
        QString dataDir;
        QString rewardAddress;
        QString connectEndpoint;
        quint64 cycles{0};
        quint64 blockCycles{1};
        quint32 threads{1};
        quint64 syncWaitMs{0};
        bool debug{false};
    };

    explicit MinerController(QObject* parent = nullptr);

    bool isRunning() const;
    void startMining(const LaunchConfig& config);
    void stopMining();

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

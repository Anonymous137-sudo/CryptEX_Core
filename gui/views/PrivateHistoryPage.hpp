#pragma once

#include <QJsonObject>
#include <QVector>
#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class RpcClient;

class PrivateHistoryPage : public QWidget {
    Q_OBJECT
public:
    explicit PrivateHistoryPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

signals:
    void replyRequested(const QString& address,
                        const QString& pubkeyB64,
                        const QString& peer,
                        const QString& draft);

private:
    static QString formatTimestamp(qint64 unixTs);
    void openEntry(int row);
    void setStatus(const QString& text, bool error = false);
    void applyFilter();

    RpcClient* rpc_{nullptr};
    QVector<QJsonObject> entries_;
    QLabel* statusValue_{nullptr};
    QLineEdit* searchEdit_{nullptr};
    QSpinBox* limitSpin_{nullptr};
    QTableWidget* table_{nullptr};
    QPushButton* refreshButton_{nullptr};
};

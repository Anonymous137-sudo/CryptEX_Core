#pragma once

#include <QJsonObject>
#include <QVector>
#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QScrollArea;
class QSpinBox;
class QVBoxLayout;
class QWidget;
class RpcClient;

class ForumPage : public QWidget {
    Q_OBJECT
public:
    explicit ForumPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

signals:
    void commentRequested(const QString& channel, const QString& draft);

private:
    static QString formatTimestamp(qint64 unixTs);
    static QString excerptForCard(const QString& message);
    static QString searchableText(const QJsonObject& entry);
    void openEntry(int index);
    void rebuildCards();
    void setStatus(const QString& text, bool error = false);
    void applyFilter();

    RpcClient* rpc_{nullptr};
    QVector<QJsonObject> entries_;
    QVector<QWidget*> cardWidgets_;
    QLabel* statusValue_{nullptr};
    QLineEdit* searchEdit_{nullptr};
    QLineEdit* channelEdit_{nullptr};
    QSpinBox* limitSpin_{nullptr};
    QScrollArea* scrollArea_{nullptr};
    QWidget* cardsHost_{nullptr};
    QVBoxLayout* cardsLayout_{nullptr};
    QPushButton* refreshButton_{nullptr};
};

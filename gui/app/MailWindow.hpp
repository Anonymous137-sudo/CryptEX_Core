#pragma once

#include <QDialog>
#include <QHash>

class QTabWidget;
class RpcClient;
class MailListPage;
class MailComposePage;
class MailAccountCreatePage;
class MailAccountsPage;
class MailSecurityPage;

class MailWindow : public QDialog {
    Q_OBJECT
public:
    explicit MailWindow(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void showSection(const QString& key = QString());
    QString currentSection() const;
    void refreshCurrentSection();
    void composeMail(const QString& toMailAddress = QString(),
                     const QString& subject = QString(),
                     const QString& body = QString());

signals:
    void sectionChanged(const QString& key);

private:
    void setSection(const QString& key, const QString& label, QWidget* page);

    QTabWidget* tabs_{nullptr};
    QHash<QString, int> indices_;
    MailListPage* inboxPage_{nullptr};
    MailListPage* sentPage_{nullptr};
    MailComposePage* composePage_{nullptr};
    MailAccountCreatePage* createAccountPage_{nullptr};
    MailAccountsPage* accountsPage_{nullptr};
    MailSecurityPage* securityPage_{nullptr};
};

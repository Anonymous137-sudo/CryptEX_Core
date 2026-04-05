#pragma once

#include <QDialog>
#include <QHash>

class QTabWidget;

class NodeWindow : public QDialog {
    Q_OBJECT
public:
    explicit NodeWindow(QWidget* parent = nullptr);

    void setSection(const QString& key, const QIcon& icon, const QString& label, QWidget* page);
    void showSection(const QString& key = QString());
    QString currentSection() const;

signals:
    void sectionChanged(const QString& key);

private:
    QTabWidget* tabs_{nullptr};
    QHash<QString, int> indices_;
};

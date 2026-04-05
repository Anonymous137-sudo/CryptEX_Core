#pragma once

#include <QWidget>

class QLabel;
class QPushButton;
class QTabWidget;
class QCheckBox;
class QWidget;

class TerminalPage : public QWidget {
    Q_OBJECT
public:
    explicit TerminalPage(QWidget* parent = nullptr);
    ~TerminalPage() override;

private:
    QLabel* shellInfoLabel_{nullptr};
    QLabel* statusLabel_{nullptr};
    QTabWidget* tabWidget_{nullptr};
    QPushButton* newTabButton_{nullptr};
    QPushButton* closeTabButton_{nullptr};
    QPushButton* restartTabButton_{nullptr};
    QPushButton* stopTabButton_{nullptr};
    QPushButton* clearTabButton_{nullptr};
    QCheckBox* followOutputCheck_{nullptr};

    QWidget* currentSession() const;
    void addTerminalTab();
    void closeCurrentTab();
    void restartCurrentTab();
    void stopCurrentTab();
    void clearCurrentTab();
    void updateHeader();
    void wireSessionSignals(QWidget* session, const QString& title);
};

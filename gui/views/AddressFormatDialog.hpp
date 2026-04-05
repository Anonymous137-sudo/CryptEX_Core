#pragma once

#include <QDialog>

class QComboBox;

class AddressFormatDialog : public QDialog {
    Q_OBJECT
public:
    explicit AddressFormatDialog(const QString& title,
                                 const QString& initialFormat,
                                 const QString& description = QString(),
                                 QWidget* parent = nullptr);

    QString selectedFormat() const;

private:
    QComboBox* formatCombo_{nullptr};
};

#include "AddressFormatDialog.hpp"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QLabel>
#include <QVBoxLayout>

AddressFormatDialog::AddressFormatDialog(const QString& title,
                                         const QString& initialFormat,
                                         const QString& description,
                                         QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(title);
    setModal(true);
    resize(360, 150);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(16, 16, 16, 16);
    root->setSpacing(12);

    auto* blurb = new QLabel(description.isEmpty()
                                 ? QStringLiteral("Choose how this address should be displayed.")
                                 : description,
                             this);
    blurb->setWordWrap(true);
    root->addWidget(blurb);

    formatCombo_ = new QComboBox(this);
    formatCombo_->addItem(QStringLiteral("Base64 (CryptEX native)"), QStringLiteral("base64"));
    formatCombo_->addItem(QStringLiteral("Base58 (P2PKH style)"), QStringLiteral("base58"));
    formatCombo_->addItem(QStringLiteral("0x Hex (EVM style)"), QStringLiteral("hex"));
    formatCombo_->addItem(QStringLiteral("Bech32"), QStringLiteral("bech32"));
    const auto index = formatCombo_->findData(initialFormat.trimmed().toLower());
    if (index >= 0) {
        formatCombo_->setCurrentIndex(index);
    }
    root->addWidget(formatCombo_);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    root->addWidget(buttons);
}

QString AddressFormatDialog::selectedFormat() const {
    return formatCombo_ ? formatCombo_->currentData().toString() : QStringLiteral("base64");
}

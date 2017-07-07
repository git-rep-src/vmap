#ifndef UI_H
#define UI_H

#include "highlighter.h"

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QListView>
#include <QScrollArea>
#include <QToolTip>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>

#include <QApplication>
#include <QDesktopWidget>

QT_BEGIN_NAMESPACE

class Ui_Vmap
{
public:
    QVBoxLayout *main_layout;

    void setupUi(QWidget *Vmap)
    {
        QFont font(":/font-default");
        font.setPointSize(11); // TODO: PERCENT

        QToolTip::setFont(font);

        main_layout = new QVBoxLayout(Vmap);
        main_layout->setMargin(10); // TODO: PERCENT
        main_layout->setSpacing(20); // TODO: PERCENT

        Vmap->setWindowFlags(Qt::CustomizeWindowHint);
        Vmap->setLayout(main_layout);
    }
};

class Ui_Finder
{
public:
    QLabel *name_label;
    QLabel *version_label;
    QLabel *cve_label;
    QLabel *match_label;
    QLabel *type_label;
    QLabel *score_label;
    QLabel *date_label;
    QLabel *order_label;
    QLabel *max_label;
    QLineEdit *name_lineedit;
    QLineEdit *version_lineedit;
    QLineEdit *cve_lineedit;
    QComboBox *match_combo;
    QComboBox *type_combo;
    QLineEdit *score_lineedit;
    QComboBox *date_combo;
    QComboBox *order_combo;
    QComboBox *max_combo;
    QPushButton *request_button;
    QGridLayout *layout;

    void setupUi(QWidget *Finder)
    {
        QFont font(":/font-default");
        font.setPointSize(11); // TODO: PERCENT
        font.setCapitalization(QFont::AllUppercase);

        name_label = new QLabel(Finder);
        name_label->setProperty("type", "gray-dark");
        name_label->setFont(font);
        name_label->setAlignment(Qt::AlignCenter);
        name_label->setText("NAME");

        name_lineedit = new QLineEdit(Finder);
        name_lineedit->setFont(font);
        name_lineedit->setMinimumHeight(30); // TODO: PERCENT
        name_lineedit->setAlignment(Qt::AlignCenter);
        name_lineedit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

        version_label = new QLabel(Finder);
        version_label->setProperty("type", "gray-dark");
        version_label->setFont(font);
        version_label->setAlignment(Qt::AlignCenter);
        version_label->setText("VERSION");

        version_lineedit = new QLineEdit(Finder);
        version_lineedit->setFont(font);
        version_lineedit->setMinimumHeight(30); // TODO: PERCENT
        version_lineedit->setAlignment(Qt::AlignCenter);
        version_lineedit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

        cve_label = new QLabel(Finder);
        cve_label->setProperty("type", "gray-dark");
        cve_label->setFont(font);
        cve_label->setAlignment(Qt::AlignCenter);
        cve_label->setText("CVE");

        cve_lineedit = new QLineEdit(Finder);
        cve_lineedit->setFont(font);
        cve_lineedit->setMinimumHeight(30); // TODO: PERCENT
        cve_lineedit->setAlignment(Qt::AlignCenter);
        cve_lineedit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        cve_lineedit->setPlaceholderText("YYYY-0000");

        match_label = new QLabel(Finder);
        match_label->setProperty("type", "gray-dark");
        match_label->setFont(font);
        match_label->setContentsMargins(0, 0, 22, 0); // TODO: PERCENT
        match_label->setAlignment(Qt::AlignCenter);
        match_label->setText("MATCH");

        match_combo = new QComboBox(Finder);
        match_combo->setMinimumHeight(29); // TODO: PERCENT
        match_combo->setEditable(true);
        match_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        match_combo->setView(new QListView());
        match_combo->lineEdit()->setReadOnly(true);
        match_combo->lineEdit()->setFont(font);
        match_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        match_combo->addItem("EXACT");
        match_combo->addItem("RELAX");
        for (int i = 0; i < match_combo->count(); ++i)
            match_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);

        type_label = new QLabel(Finder);
        type_label->setProperty("type", "gray-dark");
        type_label->setFont(font);
        type_label->setContentsMargins(0, 0, 22, 0); // TODO: PERCENT
        type_label->setAlignment(Qt::AlignCenter);
        type_label->setText("TYPE");

        type_combo = new QComboBox(Finder);
        type_combo->setMinimumHeight(29); // TODO: PERCENT
        type_combo->setEditable(true);
        type_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        type_combo->setView(new QListView());
        type_combo->lineEdit()->setReadOnly(true);
        type_combo->lineEdit()->setFont(font);
        type_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        type_combo->addItem("CVE");
        type_combo->addItem("EXPLOIT");
        for (int i = 0; i < type_combo->count(); ++i)
            type_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);

        score_label = new QLabel(Finder);
        score_label->setProperty("type", "gray-dark");
        score_label->setFont(font);
        score_label->setAlignment(Qt::AlignCenter);
        score_label->setText("SCORE");

        score_lineedit = new QLineEdit(Finder);
        score_lineedit->setFont(font);
        score_lineedit->setMinimumHeight(30); // TODO: PERCENT
        score_lineedit->setAlignment(Qt::AlignCenter);
        score_lineedit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        score_lineedit->setPlaceholderText("MIN-MAX");

        date_label = new QLabel(Finder);
        date_label->setProperty("type", "gray-dark");
        date_label->setFont(font);
        date_label->setContentsMargins(0, 0, 22, 0); // TODO: PERCENT
        date_label->setAlignment(Qt::AlignCenter);
        date_label->setText("DATE");

        date_combo = new QComboBox(Finder);
        date_combo->setMinimumHeight(29); // TODO: PERCENT
        date_combo->setEditable(true);
        date_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        date_combo->setView(new QListView());
        date_combo->lineEdit()->setReadOnly(true);
        date_combo->lineEdit()->setFont(font);
        date_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        date_combo->addItem("ALL");
        date_combo->addItem("LAST 10 DAYS");
        date_combo->addItem("LAST MONTH");
        date_combo->addItem("LAST 6 MONTH");
        date_combo->addItem("LAST YEAR");
        for (int i = 0; i < date_combo->count(); ++i)
            date_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);

        order_label = new QLabel(Finder);
        order_label->setProperty("type", "gray-dark");
        order_label->setFont(font);
        order_label->setContentsMargins(0, 0, 22, 0); // TODO: PERCENT
        order_label->setAlignment(Qt::AlignCenter);
        order_label->setText("ORDER");

        order_combo = new QComboBox(Finder);
        order_combo->setMinimumHeight(29); // TODO: PERCENT
        order_combo->setEditable(true);
        order_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        order_combo->setView(new QListView());
        order_combo->lineEdit()->setReadOnly(true);
        order_combo->lineEdit()->setFont(font);
        order_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        order_combo->addItem("DATE");
        order_combo->addItem("SCORE");
        for (int i = 0; i < order_combo->count(); ++i)
            order_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);

        max_label = new QLabel(Finder);
        max_label->setProperty("type", "gray-dark");
        max_label->setFont(font);
        max_label->setContentsMargins(0, 0, 22, 0); // TODO: PERCENT
        max_label->setAlignment(Qt::AlignCenter);
        max_label->setText("MAX");

        max_combo = new QComboBox(Finder);
        max_combo->setMinimumWidth(78); // TODO: PERCENT
        max_combo->setMinimumHeight(29); // TODO: PERCENT
        max_combo->setEditable(true);
        max_combo->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        max_combo->setView(new QListView());
        max_combo->lineEdit()->setReadOnly(true);
        max_combo->lineEdit()->setFont(font);
        max_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        max_combo->addItem("1");
        max_combo->addItem("5");
        max_combo->addItem("10");
        max_combo->addItem("20");
        max_combo->addItem("50");
        max_combo->addItem("100");
        max_combo->addItem("500");
        for (int i = 0; i < max_combo->count(); ++i)
            max_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        max_combo->setCurrentIndex(1);

        request_button = new QPushButton(QIcon(":/icon-find"), NULL, Finder);
        request_button->setIconSize(QSize(12, 12)); // TODO: PERCENT
        request_button->setFlat(true);

        layout = new QGridLayout(Finder);
        layout->setMargin(0);
        layout->setHorizontalSpacing(3); // TODO: PERCENT
        layout->setVerticalSpacing(1);
        layout->addWidget(name_label, 0, 0, 1, 1);
        layout->addWidget(name_lineedit, 1, 0, 1, 1);
        layout->addWidget(version_label, 0, 1, 1, 1);
        layout->addWidget(version_lineedit, 1, 1, 1, 1);
        layout->addWidget(cve_label, 0, 2, 1, 1);
        layout->addWidget(cve_lineedit, 1, 2, 1, 1);
        layout->addWidget(match_label, 0, 3, 1, 1);
        layout->addWidget(match_combo, 1, 3, 1, 1);
        layout->addWidget(type_label, 0, 4, 1, 1);
        layout->addWidget(type_combo, 1, 4, 1, 1);
        layout->addWidget(score_label, 0, 5, 1, 1);
        layout->addWidget(score_lineedit, 1, 5, 1, 1);
        layout->addWidget(date_label, 0, 6, 1, 1);
        layout->addWidget(date_combo, 1, 6, 1, 1);
        layout->addWidget(order_label, 0, 7, 1, 1);
        layout->addWidget(order_combo, 1, 7, 1, 1);
        layout->addWidget(max_label, 0, 8, 1, 1);
        layout->addWidget(max_combo, 1, 8, 1, 1);
        layout->addWidget(request_button, 1, 9, 1, 1);

        Finder->setLayout(layout);
    }
};

class Ui_View
{
public:
    QLabel *counter_label;
    QPushButton *request_button;
    QWidget *scroll_widget;
    QScrollArea *scroll_area;
    QHBoxLayout *counter_layout;
    QVBoxLayout *scroll_layout;
    QVBoxLayout *layout;

    void setupUi(QWidget *View)
    {
        int height = QApplication::desktop()->screenGeometry().height();

        QFont font(":/font-default");
        font.setPointSize(11); // TODO: PERCENT

        counter_label = new QLabel(View);
        counter_label->setProperty("type", "white");
        counter_label->setFont(font);
        counter_label->setMinimumWidth(75); // TODO: PERCENT
        counter_label->setMinimumHeight(30); // TODO: PERCENT
        counter_label->setAlignment(Qt::AlignCenter);
        counter_label->hide();

        request_button = new QPushButton(QIcon(":/icon-find"), NULL, View);
        request_button->setIconSize(QSize(12, 12)); // TODO: PERCENT
        request_button->setFlat(true);
        request_button->setHidden(true);

        counter_layout = new QHBoxLayout;
        counter_layout->setMargin(0);
        counter_layout->setSpacing(5); // TODO: PERCENT
        counter_layout->setAlignment(Qt::AlignLeft);
        counter_layout->addWidget(counter_label);
        counter_layout->addWidget(request_button);

        scroll_widget = new QWidget(View);

        scroll_area = new QScrollArea(View);
        scroll_area->setWidgetResizable(true);
        scroll_area->setFrameStyle(QFrame::NoFrame);
        scroll_area->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scroll_area->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

        scroll_layout = new QVBoxLayout;
        scroll_layout->setMargin(0);
        scroll_layout->setSpacing(5); // TODO: PERCENT
        scroll_layout->setAlignment(Qt::AlignTop);

        scroll_widget->setLayout(scroll_layout);
        scroll_area->setWidget(scroll_widget);

        layout = new QVBoxLayout(View);
        layout->setMargin(0);
        layout->setSpacing(5); // TODO: PERCENT
        layout->addLayout(counter_layout);
        layout->addWidget(scroll_area);

        View->setMinimumHeight(height - 90); // TODO: PERCENT
        View->setMaximumHeight(height - 90); // TODO: PERCENT
        View->setLayout(layout);
    }
};

class Ui_Element
{
public:
    QLabel *number_label;
    QLabel *published_label;
    QLabel *title_label;
    QLabel *score_label;
    QLabel *description_label;
    QLabel *id_label;
    QLabel *cvss_label;
    QLabel *cvss_data_label;
    QLabel *cpe_vendor_label;
    QLabel *cpe_product_label;
    QLabel *cpe_version_label;
    QLabel *reference_label;
    QLabel *source_label;
    QTextEdit *source_textedit;
    QPushButton *details_button;
    QPushButton *source_save_button;
    Highlighter *highlighter;
    QHBoxLayout *cvss_layout;
    QHBoxLayout *cpe_layout;
    QGridLayout *source_layout;
    QGridLayout *layout;

    void setupUi(QWidget *Element)
    {
        int height = QApplication::desktop()->screenGeometry().height();
        int width = QApplication::desktop()->screenGeometry().width();

        QFont font(":/font-default");
        font.setPointSize(11); // TODO: PERCENT

        number_label = new QLabel(Element);
        number_label->setProperty("type", "gray-dark-bg");
        number_label->setFont(font);
        number_label->setMinimumWidth(75); // TODO: PERCENT
        number_label->setMinimumHeight(30); // TODO: PERCENT
        number_label->setAlignment(Qt::AlignCenter);

        published_label = new QLabel(Element);
        published_label->setProperty("type", "gray-bg");
        published_label->setFont(font);
        published_label->setMinimumWidth(116); // TODO: PERCENT
        published_label->setMinimumHeight(30); // TODO: PERCENT
        published_label->setAlignment(Qt::AlignCenter);

        title_label = new QLabel(Element);
        title_label->setProperty("type", "gray-light-bg");
        title_label->setFont(font);
        title_label->setMinimumWidth(width - 1718); // TODO: PERCENT
        title_label->setMinimumHeight(30); // TODO: PERCENT
        title_label->setMargin(8); // TODO: PERCENT

        score_label = new QLabel(Element);
        score_label->setProperty("type", "score-low");
        score_label->setFont(font);
        score_label->setMinimumWidth(75); // TODO: PERCENT
        score_label->setMinimumHeight(30); // TODO: PERCENT
        score_label->setAlignment(Qt::AlignCenter);

        details_button = new QPushButton(QIcon(":/icon-more"), NULL, Element);
        details_button->setIconSize(QSize(12, 12)); // TODO: PERCENT
        details_button->setFlat(true);

        font.setItalic(true);

        description_label = new QLabel(Element);
        description_label->setProperty("type", "white-bg");
        description_label->setFont(font);
        description_label->setMinimumHeight(30); // TODO: PERCENT
        description_label->setMargin(8); // TODO: PERCENT
        description_label->setWordWrap(true);
        description_label->setHidden(true);

        font.setItalic(false);

        id_label = new QLabel(Element);
        id_label->setProperty("type", "white");
        id_label->setFont(font);
        id_label->setMargin(8); // TODO: PERCENT
        id_label->setText("<span style=color:#a5a5a5>"
                          "ID"
                          "</span><hr>");
        id_label->setWordWrap(true);
        id_label->setHidden(true);

        cvss_label = new QLabel(Element);
        cvss_label->setFont(font);
        cvss_label->setMargin(8); // TODO: PERCENT
        cvss_label->setText("<span style=color:#a5a5a5>"
                            "VECTOR<hr>COMPLEXITY<hr>CONFIDENTIALITY<hr>"
                            "INTEGRITY<hr>AVAILABILITY"
                            "</span>");
        cvss_label->setHidden(true);

        cvss_data_label = new QLabel(Element);
        cvss_data_label->setProperty("type", "white");
        cvss_data_label->setFont(font);
        cvss_data_label->setMargin(8); // TODO: PERCENT
        cvss_data_label->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        cvss_data_label->setHidden(true);

        cvss_layout = new QHBoxLayout;
        cvss_layout->setMargin(0);
        cvss_layout->setSpacing(1);
        cvss_layout->addWidget(cvss_label);
        cvss_layout->addWidget(cvss_data_label);

        font.setCapitalization(QFont::AllUppercase);

        cpe_vendor_label = new QLabel(Element);
        cpe_vendor_label->setProperty("type", "white");
        cpe_vendor_label->setFont(font);
        cpe_vendor_label->setMargin(8); // TODO: PERCENT
        cpe_vendor_label->setText("<span style=color:#a5a5a5>"
                                  "VENDOR"
                                  "</span><hr>");
        cpe_vendor_label->setHidden(true);

        cpe_product_label = new QLabel(Element);
        cpe_product_label->setProperty("type", "white");
        cpe_product_label->setFont(font);
        cpe_product_label->setMargin(8); // TODO: PERCENT
        cpe_product_label->setText("<span style=color:#a5a5a5>"
                                   "PRODUCT"
                                   "</span><hr>");
        cpe_product_label->setHidden(true);

        cpe_version_label = new QLabel(Element);
        cpe_version_label->setProperty("type", "white");
        cpe_version_label->setFont(font);
        cpe_version_label->setMargin(8); // TODO: PERCENT
        cpe_version_label->setText("<span style=color:#a5a5a5>"
                                   "VERSION"
                                   "</span><hr>");
        cpe_version_label->setHidden(true);

        cpe_layout = new QHBoxLayout;
        cpe_layout->setMargin(0);
        cpe_layout->setSpacing(1);
        cpe_layout->addWidget(cpe_vendor_label);
        cpe_layout->addWidget(cpe_product_label);
        cpe_layout->addWidget(cpe_version_label);

        font.setCapitalization(QFont::MixedCase);

        reference_label = new QLabel(Element);
        reference_label->setFont(font);
        reference_label->setMargin(8); // TODO: PERCENT
        reference_label->setTextInteractionFlags(Qt::TextBrowserInteraction);
        reference_label->setOpenExternalLinks(true);
        reference_label->setText("<span style=color:#a5a5a5>"
                                 "REFERENCES"
                                 "</span><hr>");
        reference_label->setHidden(true);

        source_label = new QLabel(Element);
        source_label->setFont(font);
        source_label->setMargin(8); // TODO: PERCENT
        source_label->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
        source_label->setText("<span style=color:#a5a5a5>"
                              "SOURCE"
                              "</span>");
        source_label->setHidden(true);

        source_save_button = new QPushButton(QIcon(":/icon-save"), NULL, Element);
        source_save_button->setIconSize(QSize(20, 20)); // TODO: PERCENT
        source_save_button->setFixedSize(QSize(20, 20)); // TODO: PERCENT
        source_save_button->setFlat(true);
        source_save_button->setToolTip("SAVE");
        source_save_button->setHidden(true);

        source_textedit = new QTextEdit(Element);
        source_textedit->setProperty("type", "source");
        source_textedit->setFont(font);
        source_textedit->setMinimumHeight(height - 233); // TODO: PERCENT
        source_textedit->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        source_textedit->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        source_textedit->setHidden(true);

        highlighter = new Highlighter(source_textedit->document());

        source_layout = new QGridLayout;
        source_layout->setHorizontalSpacing(5); // TODO: PERCENT
        source_layout->setVerticalSpacing(1);
        source_layout->addWidget(source_label, 0, 0, 1, 1);
        source_layout->addWidget(source_save_button, 0, 1, 1, 1, Qt::AlignLeft);
        source_layout->addWidget(source_textedit, 1, 0, 1, 2);

        layout = new QGridLayout(Element);
        layout->setMargin(0);
        layout->setHorizontalSpacing(5); // TODO: PERCENT
        layout->setVerticalSpacing(20); // TODO: PERCENT
        layout->setColumnStretch(2, 1);
        layout->addWidget(number_label, 0, 0, 1, 1);
        layout->addWidget(published_label, 0, 1, 1, 1);
        layout->addWidget(title_label, 0, 2, 1, 1);
        layout->addWidget(score_label, 0, 3, 1, 1);
        layout->addWidget(details_button, 0, 4, 1, 4);
        layout->addWidget(description_label, 1, 2, 1, 1);
        layout->addWidget(id_label, 2, 2, 1, 1);
        layout->addLayout(cvss_layout, 3, 2, 1, 1);
        layout->addLayout(cpe_layout, 4, 2, 1, 1);
        layout->addWidget(reference_label, 5, 2, 1, 1);
        layout->addLayout(source_layout, 3, 2, 1, 1);

        Element->setMinimumWidth(width - 20); // TODO: PERCENT
        Element->setMaximumWidth(width - 20); // TODO: PERCENT
        Element->setLayout(layout);
    }
};

namespace Ui {
    class Vmap: public Ui_Vmap {};
    class Finder: public Ui_Finder {};
    class View: public Ui_View {};
    class Element: public Ui_Element {};
}

QT_END_NAMESPACE

#endif // UI_H

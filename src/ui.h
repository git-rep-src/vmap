#ifndef UI_H
#define UI_H

#include "custompushbutton.h"
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
#include <QStandardItemModel>

#include <QApplication>
#include <QDesktopWidget>

QT_BEGIN_NAMESPACE

class Ui_Vmap
{
public:
    QLabel *label_status;
    CustomPushButton *button_exit;
    QVBoxLayout *layout;

    void setupUi(QWidget *Vmap)
    {
        int width = QApplication::desktop()->screenGeometry().width();

        QFont font(":/font-default");
        font.setPointSize(9); // TODO: PERCENT

        label_status = new QLabel(Vmap);
        label_status->setProperty("type", "gray-dark");
        label_status->setFont(font);
        label_status->setAlignment(Qt::AlignCenter);

        button_exit = new CustomPushButton(QIcon(":/icon-exit"), NULL, Vmap);
        button_exit->setIconSize(QSize(10, 10)); // TODO: PERCENT
        button_exit->setMaximumSize(QSize(10, 10)); // TODO: PERCENT
        button_exit->move((width - 10), 0); // TODO: PERCENT
        button_exit->setFlat(true);
        button_exit->setDisabled(true);

        font.setPointSize(11); // TODO: PERCENT

        QToolTip::setFont(font);

        layout = new QVBoxLayout(Vmap);
        layout->setMargin(10); // TODO: PERCENT
        layout->setSpacing(0); // TODO: PERCENT

        Vmap->setLayout(layout);
    }
};

class Ui_Finder
{
public:
    QLineEdit *edit_name;
    QLineEdit *edit_version;
    QLineEdit *edit_cve;
    QLineEdit *edit_score;
    QComboBox *combo_match;
    QComboBox *combo_type;
    QComboBox *combo_date;
    QComboBox *combo_order;
    QComboBox *combo_max;
    QPushButton *button_request;
    QHBoxLayout *layout;

    void setupUi(QWidget *Finder)
    {
        QFont font(":/font-default");
        font.setPointSize(11); // TODO: PERCENT
        font.setCapitalization(QFont::AllUppercase);

        edit_name = new QLineEdit(Finder);
        edit_name->setFont(font);
        edit_name->setMinimumHeight(30); // TODO: PERCENT
        edit_name->setAlignment(Qt::AlignCenter);
        edit_name->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        edit_name->setPlaceholderText("NAME");

        edit_version = new QLineEdit(Finder);
        edit_version->setFont(font);
        edit_version->setMinimumHeight(30); // TODO: PERCENT
        edit_version->setAlignment(Qt::AlignCenter);
        edit_version->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        edit_version->setPlaceholderText("VERSION");

        edit_cve = new QLineEdit(Finder);
        edit_cve->setFont(font);
        edit_cve->setMinimumHeight(30); // TODO: PERCENT
        edit_cve->setAlignment(Qt::AlignCenter);
        edit_cve->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        edit_cve->setPlaceholderText("CVE-YYYY-NNNN");

        combo_match = new QComboBox(Finder);
        combo_match->setView(new QListView());
        combo_match->view()->setFont(font);
        combo_match->setMinimumHeight(29); // TODO: PERCENT
        combo_match->setEditable(true);
        combo_match->lineEdit()->setReadOnly(true);
        combo_match->lineEdit()->setFont(font);
        combo_match->lineEdit()->setAlignment(Qt::AlignCenter);
        combo_match->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        combo_match->addItem("MATCH");
        combo_match->addItem("EXACT");
        combo_match->addItem("RELAX");
        for (int i = 0; i < combo_match->count(); ++i)
            combo_match->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m1 = qobject_cast<QStandardItemModel*>(combo_match->model());
        QModelIndex i1 = m1->index(0, combo_match->modelColumn(), combo_match->rootModelIndex());
        QStandardItem *it1 = m1->itemFromIndex(i1);
        it1->setSelectable(false);

        combo_type = new QComboBox(Finder);
        combo_type->setView(new QListView());
        combo_type->view()->setFont(font);
        combo_type->setMinimumHeight(29); // TODO: PERCENT
        combo_type->setEditable(true);
        combo_type->lineEdit()->setReadOnly(true);
        combo_type->lineEdit()->setFont(font);
        combo_type->lineEdit()->setAlignment(Qt::AlignCenter);
        combo_type->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        combo_type->addItem("TYPE");
        combo_type->addItem("CVE");
        combo_type->addItem("EXPLOITDB");
        combo_type->addItem("PACKETSTORM");
        for (int i = 0; i < combo_type->count(); ++i)
            combo_type->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m2 = qobject_cast<QStandardItemModel*>(combo_type->model());
        QModelIndex i2 = m2->index(0, combo_type->modelColumn(), combo_type->rootModelIndex());
        QStandardItem *it2 = m2->itemFromIndex(i2);
        it2->setSelectable(false);

        edit_score = new QLineEdit(Finder);
        edit_score->setFont(font);
        edit_score->setMinimumHeight(30); // TODO: PERCENT
        edit_score->setAlignment(Qt::AlignCenter);
        edit_score->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        edit_score->setPlaceholderText("SCORE MIN-MAX");

        combo_date = new QComboBox(Finder);
        combo_date->setView(new QListView());
        combo_date->view()->setFont(font);
        combo_date->setMinimumHeight(29); // TODO: PERCENT
        combo_date->setEditable(true);
        combo_date->lineEdit()->setReadOnly(true);
        combo_date->lineEdit()->setFont(font);
        combo_date->lineEdit()->setAlignment(Qt::AlignCenter);
        combo_date->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        combo_date->addItem("DATE");
        combo_date->addItem("ANY");
        combo_date->addItem("LAST 10 DAYS");
        combo_date->addItem("LAST MONTH");
        combo_date->addItem("LAST 6 MONTH");
        combo_date->addItem("LAST YEAR");
        for (int i = 0; i < combo_date->count(); ++i)
            combo_date->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m3 = qobject_cast<QStandardItemModel*>(combo_date->model());
        QModelIndex i3 = m3->index(0, combo_date->modelColumn(), combo_date->rootModelIndex());
        QStandardItem *it3 = m3->itemFromIndex(i3);
        it3->setSelectable(false);

        combo_order = new QComboBox(Finder);
        combo_order->setView(new QListView());
        combo_order->view()->setFont(font);
        combo_order->setMinimumHeight(29); // TODO: PERCENT
        combo_order->setEditable(true);
        combo_order->lineEdit()->setReadOnly(true);
        combo_order->lineEdit()->setFont(font);
        combo_order->lineEdit()->setAlignment(Qt::AlignCenter);
        combo_order->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        combo_order->addItem("ORDER");
        combo_order->addItem("DATE");
        combo_order->addItem("SCORE");
        for (int i = 0; i < combo_order->count(); ++i)
            combo_order->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m4 = qobject_cast<QStandardItemModel*>(combo_order->model());
        QModelIndex i4 = m4->index(0, combo_order->modelColumn(), combo_order->rootModelIndex());
        QStandardItem *it4 = m4->itemFromIndex(i4);
        it4->setSelectable(false);

        combo_max = new QComboBox(Finder);
        combo_max->setView(new QListView());
        combo_max->view()->setFont(font);
        combo_max->setMinimumWidth(78); // TODO: PERCENT
        combo_max->setMinimumHeight(29); // TODO: PERCENT
        combo_max->setEditable(true);
        combo_max->lineEdit()->setReadOnly(true);
        combo_max->lineEdit()->setFont(font);
        combo_max->lineEdit()->setAlignment(Qt::AlignCenter);
        combo_max->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        combo_max->addItem("MAX");
        combo_max->addItem("1");
        combo_max->addItem("5");
        combo_max->addItem("10");
        combo_max->addItem("20");
        combo_max->addItem("50");
        combo_max->addItem("100");
        combo_max->addItem("500");
        for (int i = 0; i < combo_max->count(); ++i)
            combo_max->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m5 = qobject_cast<QStandardItemModel*>(combo_max->model());
        QModelIndex i5 = m5->index(0, combo_max->modelColumn(), combo_max->rootModelIndex());
        QStandardItem *it5 = m5->itemFromIndex(i5);
        it5->setSelectable(false);

        button_request = new QPushButton(QIcon(":/icon-find"), NULL, Finder);
        button_request->setIconSize(QSize(12, 12)); // TODO: PERCENT
        button_request->setFlat(true);

        layout = new QHBoxLayout(Finder);
        layout->setMargin(0);
        layout->setSpacing(3); // TODO: PERCENT
        layout->addWidget(edit_name);
        layout->addWidget(edit_version);
        layout->addWidget(edit_cve);
        layout->addWidget(combo_match);
        layout->addWidget(combo_type);
        layout->addWidget(edit_score);
        layout->addWidget(combo_date);
        layout->addWidget(combo_order);
        layout->addWidget(combo_max);
        layout->addWidget(button_request);

        Finder->setLayout(layout);
    }
};

class Ui_View
{
public:
    QLabel *label_counter;
    QPushButton *button_request;
    QWidget *widget_scroll;
    QScrollArea *scrollarea;
    QHBoxLayout *layout_counter;
    QVBoxLayout *layout_scroll;
    QVBoxLayout *layout;

    void setupUi(QWidget *View)
    {
        int height = QApplication::desktop()->screenGeometry().height();

        QFont font(":/font-default");
        font.setPointSize(11); // TODO: PERCENT

        label_counter = new QLabel(View);
        label_counter->setProperty("type", "white-bg");
        label_counter->setFont(font);
        label_counter->setMinimumWidth(75); // TODO: PERCENT
        label_counter->setMinimumHeight(30); // TODO: PERCENT
        label_counter->setAlignment(Qt::AlignCenter);
        label_counter->hide();

        button_request = new QPushButton(QIcon(":/icon-find"), NULL, View);
        button_request->setIconSize(QSize(12, 12)); // TODO: PERCENT
        button_request->setFlat(true);
        button_request->setHidden(true);

        layout_counter = new QHBoxLayout;
        layout_counter->setMargin(0);
        layout_counter->setSpacing(5); // TODO: PERCENT
        layout_counter->setAlignment(Qt::AlignLeft);
        layout_counter->addWidget(label_counter);
        layout_counter->addWidget(button_request);

        widget_scroll = new QWidget(View);

        scrollarea = new QScrollArea(View);
        scrollarea->setWidgetResizable(true);
        scrollarea->setFrameStyle(QFrame::NoFrame);
        scrollarea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scrollarea->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

        layout_scroll = new QVBoxLayout;
        layout_scroll->setMargin(0);
        layout_scroll->setSpacing(5); // TODO: PERCENT
        layout_scroll->setAlignment(Qt::AlignTop);

        widget_scroll->setLayout(layout_scroll);
        scrollarea->setWidget(widget_scroll);

        layout = new QVBoxLayout(View);
        layout->setMargin(0);
        layout->setSpacing(5); // TODO: PERCENT
        layout->addLayout(layout_counter);
        layout->addWidget(scrollarea);

        View->setMinimumHeight(height - 65); // TODO: PERCENT
        View->setMaximumHeight(height - 65); // TODO: PERCENT
        View->setLayout(layout);
    }
};

class Ui_Element
{
public:
    QLabel *label_number;
    QLabel *label_published;
    QLabel *label_title;
    QLabel *label_score;
    QLabel *label_description;
    QLabel *label_id;
    QLabel *label_cve;
    QLabel *label_cvss;
    QLabel *label_cpe_vendor;
    QLabel *label_cpe_product;
    QLabel *label_cpe_version;
    QLabel *label_href;
    QLabel *label_source;
    QTextEdit *text_source;
    QPushButton *button_details;
    QPushButton *button_save;
    Highlighter *highlighter;
    QHBoxLayout *layout_cpe;
    QVBoxLayout *layout_source;
    QGridLayout *layout;

    void setupUi(QWidget *Element)
    {
        int height = QApplication::desktop()->screenGeometry().height();
        int width = QApplication::desktop()->screenGeometry().width();

        QFont font(":/font-default");
        font.setPointSize(11); // TODO: PERCENT

        label_number = new QLabel(Element);
        label_number->setProperty("type", "gray-dark-bg");
        label_number->setFont(font);
        label_number->setMinimumWidth(75); // TODO: PERCENT
        label_number->setMinimumHeight(30); // TODO: PERCENT
        label_number->setAlignment(Qt::AlignCenter);

        label_published = new QLabel(Element);
        label_published->setProperty("type", "gray-bg");
        label_published->setFont(font);
        label_published->setMinimumWidth(116); // TODO: PERCENT
        label_published->setMinimumHeight(30); // TODO: PERCENT
        label_published->setAlignment(Qt::AlignCenter);

        label_title = new QLabel(Element);
        label_title->setProperty("type", "gray-light-bg");
        label_title->setFont(font);
        label_title->setMinimumWidth(width - 1718); // TODO: PERCENT
        label_title->setMinimumHeight(30); // TODO: PERCENT
        label_title->setMargin(8); // TODO: PERCENT
        label_title->setTextInteractionFlags(Qt::TextSelectableByMouse);

        label_score = new QLabel(Element);
        label_score->setProperty("type", "score-low");
        label_score->setFont(font);
        label_score->setMinimumWidth(75); // TODO: PERCENT
        label_score->setMinimumHeight(30); // TODO: PERCENT
        label_score->setAlignment(Qt::AlignCenter);

        button_details = new QPushButton(QIcon(":/icon-more"), NULL, Element);
        button_details->setIconSize(QSize(12, 12)); // TODO: PERCENT
        button_details->setFlat(true);

        font.setItalic(true);

        label_description = new QLabel(Element);
        label_description->setProperty("type", "white-bg");
        label_description->setFont(font);
        label_description->setMinimumHeight(30); // TODO: PERCENT
        label_description->setMargin(8); // TODO: PERCENT
        label_description->setWordWrap(true);
        label_description->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_description->setHidden(true);

        font.setItalic(false);

        label_id = new QLabel(Element);
        label_id->setProperty("type", "white");
        label_id->setFont(font);
        label_id->setMargin(8); // TODO: PERCENT
        label_id->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_id->setText("<span style=color:#998f46>"
                          "ID"
                          "</span><hr>");
        label_id->setHidden(true);

        label_cve = new QLabel(Element);
        label_cve->setProperty("type", "white");
        label_cve->setFont(font);
        label_cve->setMargin(8); // TODO: PERCENT
        label_cve->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_cve->setText("<span style=color:#998f46>"
                           "CVE"
                           "</span><hr>");
        label_cve->setHidden(true);

        label_cvss = new QLabel(Element);
        label_cvss->setFont(font);
        label_cvss->setMargin(8); // TODO: PERCENT
        label_cvss->setText("<span style=color:#998f46>"
                            "CVSS"
                            "</span><hr>");
        label_cvss->setHidden(true);

        font.setCapitalization(QFont::AllUppercase);

        label_cpe_vendor = new QLabel(Element);
        label_cpe_vendor->setProperty("type", "white");
        label_cpe_vendor->setFont(font);
        label_cpe_vendor->setMargin(8); // TODO: PERCENT
        label_cpe_vendor->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_cpe_vendor->setText("<span style=color:#998f46>"
                                  "VENDOR"
                                  "</span><hr>");
        label_cpe_vendor->setHidden(true);

        label_cpe_product = new QLabel(Element);
        label_cpe_product->setProperty("type", "white");
        label_cpe_product->setFont(font);
        label_cpe_product->setMargin(8); // TODO: PERCENT
        label_cpe_product->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_cpe_product->setText("<span style=color:#998f46>"
                                   "PRODUCT"
                                   "</span><hr>");
        label_cpe_product->setHidden(true);

        label_cpe_version = new QLabel(Element);
        label_cpe_version->setProperty("type", "white");
        label_cpe_version->setFont(font);
        label_cpe_version->setMargin(8); // TODO: PERCENT
        label_cpe_version->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_cpe_version->setText("<span style=color:#998f46>"
                                   "VERSION"
                                   "</span><hr>");
        label_cpe_version->setHidden(true);

        layout_cpe = new QHBoxLayout;
        layout_cpe->setMargin(0);
        layout_cpe->setSpacing(0);
        layout_cpe->addWidget(label_cpe_vendor);
        layout_cpe->addWidget(label_cpe_product);
        layout_cpe->addWidget(label_cpe_version);

        font.setCapitalization(QFont::MixedCase);

        label_href = new QLabel(Element);
        label_href->setFont(font);
        label_href->setMargin(8); // TODO: PERCENT
        label_href->setTextInteractionFlags(Qt::TextBrowserInteraction | Qt::TextSelectableByMouse);
        label_href->setOpenExternalLinks(true);
        label_href->setText("<span style=color:#998f46>"
                            "REFERENCES"
                            "</span><hr>");
        label_href->setHidden(true);

        label_source = new QLabel(Element);
        label_source->setFont(font);
        label_source->setContentsMargins(0, 8, 0, 0); // TODO: PERCENT
        label_source->setText("<span style=color:#998f46>"
                              "SOURCE"
                              "</span><hr>");
        label_source->setHidden(true);

        text_source = new QTextEdit(Element);
        text_source->setProperty("type", "source");
        text_source->setFont(font);
        text_source->setMinimumHeight(height - 142); // TODO: PERCENT
        text_source->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        text_source->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        text_source->setReadOnly(true);
        text_source->setHidden(true);

        highlighter = new Highlighter(text_source->document());

        button_save = new QPushButton(QIcon(":/icon-save"), NULL, text_source);
        button_save->setIconSize(QSize(20, 20)); // TODO: PERCENT
        button_save->setMaximumWidth(20); // TODO: PERCENT
        button_save->move(1525, 5); // TODO: CALCULATE
        button_save->setFlat(true);
        button_save->setToolTip("SAVE");
        button_save->setHidden(true);

        layout_source = new QVBoxLayout;
        layout_source->setContentsMargins(8, 0, 8, 0); // TODO: PERCENT
        layout_source->setSpacing(0);
        layout_source->addWidget(label_source);
        layout_source->addWidget(text_source);

        layout = new QGridLayout(Element);
        layout->setMargin(0);
        layout->setHorizontalSpacing(5); // TODO: PERCENT
        layout->setVerticalSpacing(15); // TODO: PERCENT
        layout->setColumnStretch(2, 1);
        layout->addWidget(label_number, 0, 0, 1, 1);
        layout->addWidget(label_published, 0, 1, 1, 1);
        layout->addWidget(label_title, 0, 2, 1, 1);
        layout->addWidget(label_score, 0, 3, 1, 1);
        layout->addWidget(button_details, 0, 4, 1, 4);
        layout->addWidget(label_description, 1, 2, 1, 1);
        layout->addWidget(label_id, 2, 2, 1, 1);
        layout->addWidget(label_cve, 3, 2, 1, 1);
        layout->addWidget(label_cvss, 4, 2, 1, 1);
        layout->addLayout(layout_cpe, 5, 2, 1, 1);
        layout->addWidget(label_href, 6, 2, 1, 1);
        layout->addLayout(layout_source, 7, 2, 1, 1);

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

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
        int desktop_width = QApplication::desktop()->screenGeometry().width();
        int base_size = (desktop_width / 192);
        int base_margin = (desktop_width / 192);

        QFont font(":/font-default");
        font.setPointSize(desktop_width / 213.3);

        label_status = new QLabel(Vmap);
        label_status->setProperty("type", "gray-dark");
        label_status->setFont(font);
        label_status->setAlignment(Qt::AlignCenter);

        button_exit = new CustomPushButton(QIcon(":/icon-exit"), NULL, Vmap);
        button_exit->setIconSize(QSize(base_size, base_size));
        button_exit->setMaximumSize(QSize(base_size, base_size));
        button_exit->move((desktop_width - base_margin), 0);
        button_exit->setFlat(true);
        button_exit->setDisabled(true);

        font.setPointSize(desktop_width / 174.5);

        QToolTip::setFont(font);

        layout = new QVBoxLayout(Vmap);
        layout->setMargin(base_margin);
        layout->setSpacing(0);

        Vmap->setLayout(layout);
    }
};

class Ui_Finder
{
public:
    QLineEdit *edit_id;
    QLineEdit *edit_cve;
    QLineEdit *edit_nmap;
    QLineEdit *edit_name;
    QLineEdit *edit_version;
    QLineEdit *edit_score;
    QComboBox *combo_match;
    QComboBox *combo_vector;
    QComboBox *combo_type;
    QComboBox *combo_date;
    QComboBox *combo_order;
    QComboBox *combo_max;
    QPushButton *button_nmap;
    QPushButton *button_request;
    QHBoxLayout *layout_nmap;
    QHBoxLayout *layout;

    void setupUi(QWidget *Finder)
    {
        int desktop_width = QApplication::desktop()->screenGeometry().width();
        int desktop_height = QApplication::desktop()->screenGeometry().height();
        int base_height = (desktop_height / 36);
        int base_size = (desktop_width / 160);

        QFont font(":/font-default");
        font.setPointSize(desktop_width / 174.5);
        font.setCapitalization(QFont::AllUppercase);

        edit_id = new QLineEdit(Finder);
        edit_id->setFont(font);
        edit_id->setMinimumHeight(base_height);
        edit_id->setAlignment(Qt::AlignCenter);
        edit_id->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        edit_id->setPlaceholderText("ID");

        edit_cve = new QLineEdit(Finder);
        edit_cve->setFont(font);
        edit_cve->setMinimumHeight(base_height);
        edit_cve->setAlignment(Qt::AlignCenter);
        edit_cve->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        edit_cve->setPlaceholderText("CVE");
        edit_cve->setToolTip("CVE-YYYY-NNNN");

        edit_nmap = new QLineEdit(Finder);
        edit_nmap->setFont(font);
        edit_nmap->setMinimumHeight(base_height);
        edit_nmap->setAlignment(Qt::AlignCenter);
        edit_nmap->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        edit_nmap->setPlaceholderText("NMAP");
        edit_nmap->setToolTip("NMAP XML FILE");

        button_nmap = new QPushButton("+", Finder);
        button_nmap->setProperty("type", "file");
        button_nmap->setMaximumSize(QSize((desktop_width / 87), base_height));

        layout_nmap = new QHBoxLayout;
        layout_nmap->setMargin(0);
        layout_nmap->setSpacing(0);
        layout_nmap->addWidget(edit_nmap);
        layout_nmap->addWidget(button_nmap);

        edit_name = new QLineEdit(Finder);
        edit_name->setFont(font);
        edit_name->setMinimumHeight(base_height);
        edit_name->setAlignment(Qt::AlignCenter);
        edit_name->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        edit_name->setPlaceholderText("NAME");

        edit_version = new QLineEdit(Finder);
        edit_version->setFont(font);
        edit_version->setMinimumHeight(base_height);
        edit_version->setAlignment(Qt::AlignCenter);
        edit_version->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        edit_version->setPlaceholderText("VERSION");

        combo_match = new QComboBox(Finder);
        combo_match->setView(new QListView());
        combo_match->view()->setFont(font);
        combo_match->setMinimumHeight(base_height - 1);
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

        combo_vector = new QComboBox(Finder);
        combo_vector->setView(new QListView());
        combo_vector->view()->setFont(font);
        combo_vector->setMinimumHeight(base_height - 1);
        combo_vector->setEditable(true);
        combo_vector->lineEdit()->setReadOnly(true);
        combo_vector->lineEdit()->setFont(font);
        combo_vector->lineEdit()->setAlignment(Qt::AlignCenter);
        combo_vector->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        combo_vector->addItem("VECTOR");
        combo_vector->addItem("ANY");
        combo_vector->addItem("LOCAL");
        combo_vector->addItem("REMOTE");
        combo_vector->addItem("ADJACENT");
        combo_vector->addItem("PHYSICAL");
        for (int i = 0; i < combo_vector->count(); ++i)
            combo_vector->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m2 = qobject_cast<QStandardItemModel*>(combo_vector->model());
        QModelIndex i2 = m2->index(0, combo_vector->modelColumn(), combo_vector->rootModelIndex());
        QStandardItem *it2 = m2->itemFromIndex(i2);
        it2->setSelectable(false);

        combo_type = new QComboBox(Finder);
        combo_type->setView(new QListView());
        combo_type->view()->setFont(font);
        combo_type->setMinimumHeight(base_height - 1);
        combo_type->setEditable(true);
        combo_type->lineEdit()->setReadOnly(true);
        combo_type->lineEdit()->setFont(font);
        combo_type->lineEdit()->setAlignment(Qt::AlignCenter);
        combo_type->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        combo_type->addItem("TYPE");
        combo_type->addItem("CVE");
        combo_type->addItem("EXPLOITDB");
        combo_type->addItem("PACKETSTORM");
        combo_type->addItem("WORDPRESSDB");
        for (int i = 0; i < combo_type->count(); ++i)
            combo_type->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m3 = qobject_cast<QStandardItemModel*>(combo_type->model());
        QModelIndex i3 = m3->index(0, combo_type->modelColumn(), combo_type->rootModelIndex());
        QStandardItem *it3 = m3->itemFromIndex(i3);
        it3->setSelectable(false);

        edit_score = new QLineEdit(Finder);
        edit_score->setFont(font);
        edit_score->setMinimumHeight(base_height);
        edit_score->setAlignment(Qt::AlignCenter);
        edit_score->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        edit_score->setPlaceholderText("SCORE");
        edit_score->setToolTip("MIN-MAX");

        combo_date = new QComboBox(Finder);
        combo_date->setView(new QListView());
        combo_date->view()->setFont(font);
        combo_date->setMinimumHeight(base_height - 1);
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
        QStandardItemModel *m4 = qobject_cast<QStandardItemModel*>(combo_date->model());
        QModelIndex i4 = m4->index(0, combo_date->modelColumn(), combo_date->rootModelIndex());
        QStandardItem *it4 = m4->itemFromIndex(i4);
        it4->setSelectable(false);

        combo_order = new QComboBox(Finder);
        combo_order->setView(new QListView());
        combo_order->view()->setFont(font);
        combo_order->setMinimumHeight(base_height - 1);
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
        QStandardItemModel *m5 = qobject_cast<QStandardItemModel*>(combo_order->model());
        QModelIndex i5 = m5->index(0, combo_order->modelColumn(), combo_order->rootModelIndex());
        QStandardItem *it5 = m5->itemFromIndex(i5);
        it5->setSelectable(false);

        combo_max = new QComboBox(Finder);
        combo_max->setView(new QListView());
        combo_max->view()->setFont(font);
        combo_max->setMinimumWidth(desktop_width / 24.6);
        combo_max->setMinimumHeight(base_height - 1);
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
        QStandardItemModel *m6 = qobject_cast<QStandardItemModel*>(combo_max->model());
        QModelIndex i6 = m6->index(0, combo_max->modelColumn(), combo_max->rootModelIndex());
        QStandardItem *it6 = m6->itemFromIndex(i6);
        it6->setSelectable(false);

        button_request = new QPushButton(QIcon(":/icon-find"), NULL, Finder);
        button_request->setIconSize(QSize(base_size, base_size));
        button_request->setFlat(true);

        layout = new QHBoxLayout(Finder);
        layout->setMargin(0);
        layout->setSpacing(3);
        layout->addWidget(edit_id);
        layout->addWidget(edit_cve);
        layout->addLayout(layout_nmap);
        layout->addWidget(edit_name);
        layout->addWidget(edit_version);
        layout->addWidget(combo_match);
        layout->addWidget(combo_vector);
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
        int desktop_width = QApplication::desktop()->screenGeometry().width();
        int desktop_height = QApplication::desktop()->screenGeometry().height();
        int base_height = (desktop_height / 31.7);
        int base_size = (desktop_width / 76.8);
        int base_space = (desktop_width / 384);

        QFont font(":/font-default");
        font.setPointSize(desktop_width / 174.5);

        label_counter = new QLabel(View);
        label_counter->setProperty("type", "white");
        label_counter->setFont(font);
        label_counter->setMinimumWidth(desktop_width / 25.6);
        label_counter->setMinimumHeight(base_height);
        label_counter->setAlignment(Qt::AlignCenter);
        label_counter->hide();

        button_request = new QPushButton("→", View);
        button_request->setFont(font);
        button_request->setMaximumSize(QSize(base_size, base_size));
        button_request->setFlat(true);
        button_request->setHidden(true);

        layout_counter = new QHBoxLayout;
        layout_counter->setMargin(0);
        layout_counter->setSpacing(base_space);
        layout_counter->setAlignment(Qt::AlignRight);
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
        layout_scroll->setSpacing(base_space);
        layout_scroll->setAlignment(Qt::AlignTop);

        widget_scroll->setLayout(layout_scroll);
        scrollarea->setWidget(widget_scroll);

        layout = new QVBoxLayout(View);
        layout->setMargin(0);
        layout->setSpacing(base_space);
        layout->addLayout(layout_counter);
        layout->addWidget(scrollarea);

        View->setMinimumHeight(desktop_height - (desktop_height / 16.6));
        View->setMaximumHeight(desktop_height - (desktop_height / 16.6));
        View->setLayout(layout);
    }
};

class Ui_Bulletin
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
    QLabel *label_source_line;
    QTextEdit *text_source;
    QPushButton *button_details;
    QPushButton *button_source_details;
    QPushButton *button_source_save;
    Highlighter *highlighter;
    QHBoxLayout *layout_cpe;
    QHBoxLayout *layout_source_label;
    QVBoxLayout *layout_source;
    QGridLayout *layout;

    void setupUi(QWidget *Bulletin)
    {
        int desktop_width = QApplication::desktop()->screenGeometry().width();
        int desktop_height = QApplication::desktop()->screenGeometry().height();
        int base_height = (desktop_height / 31.7);
        int base_size = (desktop_width / 160);
        int base_margin = (desktop_width / 240);
        int base_space = (desktop_width / 384);

        QFont font(":/font-default");
        font.setPointSize(desktop_width / 174.5);

        label_number = new QLabel(Bulletin);
        label_number->setProperty("type", "gray-dark-bg");
        label_number->setFont(font);
        label_number->setMinimumWidth(desktop_width / 25.6);
        label_number->setMinimumHeight(base_height);
        label_number->setAlignment(Qt::AlignCenter);

        label_published = new QLabel(Bulletin);
        label_published->setProperty("type", "gray-bg");
        label_published->setFont(font);
        label_published->setMinimumWidth(desktop_width / 16.5);
        label_published->setMinimumHeight(base_height);
        label_published->setAlignment(Qt::AlignCenter);

        label_title = new QLabel(Bulletin);
        label_title->setProperty("type", "gray-light-bg");
        label_title->setFont(font);
        label_title->setMinimumWidth(desktop_width - (desktop_width / 1.1175));
        label_title->setMinimumHeight(base_height);
        label_title->setMargin(base_margin);
        label_title->setTextInteractionFlags(Qt::TextSelectableByMouse);

        label_score = new QLabel(Bulletin);
        label_score->setProperty("type", "score-low");
        label_score->setFont(font);
        label_score->setMinimumWidth(desktop_width / 25.6);
        label_score->setMinimumHeight(base_height);
        label_score->setAlignment(Qt::AlignCenter);

        button_details = new QPushButton(QIcon(":/icon-more"), NULL, Bulletin);
        button_details->setIconSize(QSize(base_size, base_size));
        button_details->setFlat(true);

        font.setItalic(true);

        label_description = new QLabel(Bulletin);
        label_description->setProperty("type", "white-bg");
        label_description->setFont(font);
        label_description->setMinimumHeight(base_height);
        label_description->setMargin(base_margin);
        label_description->setWordWrap(true);
        label_description->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_description->setHidden(true);

        font.setItalic(false);

        label_id = new QLabel(Bulletin);
        label_id->setProperty("type", "white");
        label_id->setFont(font);
        label_id->setMargin(base_margin);
        label_id->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_id->setText("<span style=color:#998f46>ID</span><hr>");
        label_id->setHidden(true);

        label_cve = new QLabel(Bulletin);
        label_cve->setProperty("type", "white");
        label_cve->setFont(font);
        label_cve->setMargin(base_margin);
        label_cve->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_cve->setText("<span style=color:#998f46>CVE</span><hr>");
        label_cve->setHidden(true);

        label_cvss = new QLabel(Bulletin);
        label_cvss->setFont(font);
        label_cvss->setMargin(base_margin);
        label_cvss->setText("<span style=color:#998f46>CVSS</span><hr>");
        label_cvss->setHidden(true);

        font.setCapitalization(QFont::AllUppercase);

        label_cpe_vendor = new QLabel(Bulletin);
        label_cpe_vendor->setProperty("type", "white");
        label_cpe_vendor->setFont(font);
        label_cpe_vendor->setMargin(base_margin);
        label_cpe_vendor->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_cpe_vendor->setText("<span style=color:#998f46>VENDOR</span><hr>");
        label_cpe_vendor->setHidden(true);

        label_cpe_product = new QLabel(Bulletin);
        label_cpe_product->setProperty("type", "white");
        label_cpe_product->setFont(font);
        label_cpe_product->setMargin(base_margin);
        label_cpe_product->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_cpe_product->setText("<span style=color:#998f46>PRODUCT</span><hr>");
        label_cpe_product->setHidden(true);

        label_cpe_version = new QLabel(Bulletin);
        label_cpe_version->setProperty("type", "white");
        label_cpe_version->setFont(font);
        label_cpe_version->setMargin(base_margin);
        label_cpe_version->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label_cpe_version->setText("<span style=color:#998f46>VERSION</span><hr>");
        label_cpe_version->setHidden(true);

        layout_cpe = new QHBoxLayout;
        layout_cpe->setMargin(0);
        layout_cpe->setSpacing(0);
        layout_cpe->addWidget(label_cpe_vendor);
        layout_cpe->addWidget(label_cpe_product);
        layout_cpe->addWidget(label_cpe_version);

        font.setCapitalization(QFont::MixedCase);

        label_href = new QLabel(Bulletin);
        label_href->setFont(font);
        label_href->setMargin(base_margin);
        label_href->setTextInteractionFlags(Qt::TextBrowserInteraction | Qt::TextSelectableByMouse);
        label_href->setOpenExternalLinks(true);
        label_href->setText("<span style=color:#998f46>REFERENCES</span><hr>");
        label_href->setHidden(true);

        label_source = new QLabel(Bulletin);
        label_source->setFont(font);
        label_source->setContentsMargins(0, base_margin, 0, 0);
        label_source->setText("<span style=color:#998f46>SOURCE</span>");
        label_source->setHidden(true);

        button_source_details = new QPushButton(QIcon(":/icon-source-more"), NULL, Bulletin);
        button_source_details->setIconSize(QSize(base_size, (desktop_height / 60)));
        button_source_details->setMinimumSize(QSize(base_size, (desktop_height / 60)));
        button_source_details->setFlat(true);
        button_source_details->setHidden(true);

        layout_source_label = new QHBoxLayout;
        layout_source_label->setMargin(0);
        layout_source_label->setSpacing(base_space);
        layout_source_label->addWidget(label_source);
        layout_source_label->addWidget(button_source_details);
        layout_source_label->addStretch();

        label_source_line = new QLabel(Bulletin);
        label_source_line->setFont(font);
        label_source_line->setText("<hr>");
        label_source_line->setHidden(true);

        text_source = new QTextEdit(Bulletin);
        text_source->setProperty("type", "source");
        text_source->setFont(font);
        text_source->setMinimumHeight(desktop_height - (desktop_height / 7.6));
        text_source->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        text_source->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        text_source->setReadOnly(true);
        text_source->setHidden(true);

        highlighter = new Highlighter(text_source->document());

        button_source_save = new QPushButton(QIcon(":/icon-save"), NULL, text_source);
        button_source_save->setIconSize(QSize((desktop_width / 96), (desktop_width / 96)));
        button_source_save->setMaximumWidth(desktop_width / 96);
        button_source_save->move((desktop_width / 1.2590), base_space);
        button_source_save->setFlat(true);
        button_source_save->setToolTip("SAVE");

        layout_source = new QVBoxLayout;
        layout_source->setContentsMargins(base_margin, 0, base_margin, 0);
        layout_source->setSpacing(0);
        layout_source->addLayout(layout_source_label);
        layout_source->addWidget(label_source_line);
        layout_source->addWidget(text_source);

        layout = new QGridLayout(Bulletin);
        layout->setMargin(0);
        layout->setHorizontalSpacing(base_space);
        layout->setVerticalSpacing(desktop_height / 72);
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

        Bulletin->setMinimumWidth(desktop_width - (desktop_width / 96));
        Bulletin->setMaximumWidth(desktop_width - (desktop_width / 96));
        Bulletin->setLayout(layout);
    }
};

namespace Ui {
    class Vmap: public Ui_Vmap {};
    class Finder: public Ui_Finder {};
    class View: public Ui_View {};
    class Bulletin: public Ui_Bulletin {};
}

QT_END_NAMESPACE

#endif // UI_H

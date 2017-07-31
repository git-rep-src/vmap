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
    QLabel *status_label;
    CustomPushButton *exit_button;
    QVBoxLayout *layout;

    void setupUi(QWidget *Vmap)
    {
        int desktop_width = QApplication::desktop()->screenGeometry().width();
        int desktop_height = QApplication::desktop()->screenGeometry().height();
        int base_height = (desktop_height / 54);
        int base_size = (desktop_width / 192);
        int base_margin = (desktop_width / 192);

        QFont font(":/font-default");
        font.setPointSize(desktop_width / 174.5);

        status_label = new QLabel(Vmap);
        status_label->setProperty("type", "gray-dark");
        status_label->setFont(font);
        status_label->setMinimumHeight(base_height);
        status_label->setAlignment(Qt::AlignHCenter | Qt::AlignBottom);

        exit_button = new CustomPushButton(QIcon(":/icon-exit"), NULL, Vmap);
        exit_button->setIconSize(QSize(base_size, base_size));
        exit_button->setMaximumSize(QSize(base_size, base_size));
        exit_button->move((desktop_width - base_margin), 0);
        exit_button->setFlat(true);
        exit_button->setDisabled(true);

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
    QLineEdit *id_edit;
    QLineEdit *cve_edit;
    QLineEdit *name_edit;
    QLineEdit *version_edit;
    QLineEdit *nmap_edit;
    QLineEdit *score_edit;
    QComboBox *match_combo;
    QComboBox *vector_combo;
    QComboBox *type_combo;
    QComboBox *date_combo;
    QComboBox *order_combo;
    QComboBox *max_combo;
    QLabel *counter_offset_label;
    QLabel *counter_total_label;
    QPushButton *nmap_button;
    QPushButton *request_button;
    QPushButton *request_offset_button;
    QHBoxLayout *nmap_layout;
    QHBoxLayout *layout;

    void setupUi(QWidget *Finder)
    {
        int desktop_width = QApplication::desktop()->screenGeometry().width();
        int desktop_height = QApplication::desktop()->screenGeometry().height();
        int base_height = (desktop_height / 30.85);
        int base_size = (desktop_width / 160);
        int base_space = 1;

        QFont font(":/font-default");
        font.setPointSize(desktop_width / 174.5);
        font.setCapitalization(QFont::AllUppercase);

        id_edit = new QLineEdit(Finder);
        id_edit->setFont(font);
        id_edit->setMinimumHeight(base_height);
        id_edit->setAlignment(Qt::AlignCenter);
        id_edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        id_edit->setPlaceholderText("ID");

        cve_edit = new QLineEdit(Finder);
        cve_edit->setFont(font);
        cve_edit->setMinimumHeight(base_height);
        cve_edit->setAlignment(Qt::AlignCenter);
        cve_edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        cve_edit->setPlaceholderText("CVE");
        cve_edit->setToolTip("CVE-YYYY-NNNN");

        name_edit = new QLineEdit(Finder);
        name_edit->setFont(font);
        name_edit->setMinimumHeight(base_height);
        name_edit->setAlignment(Qt::AlignCenter);
        name_edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        name_edit->setPlaceholderText("NAME");

        version_edit = new QLineEdit(Finder);
        version_edit->setFont(font);
        version_edit->setMinimumHeight(base_height);
        version_edit->setAlignment(Qt::AlignCenter);
        version_edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        version_edit->setPlaceholderText("VERSION");

        nmap_edit = new QLineEdit(Finder);
        nmap_edit->setFont(font);
        nmap_edit->setMinimumHeight(base_height);
        nmap_edit->setAlignment(Qt::AlignCenter);
        nmap_edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        nmap_edit->setPlaceholderText("NMAP");
        nmap_edit->setToolTip("NMAP XML FILE");

        nmap_button = new QPushButton("+", Finder);
        nmap_button->setProperty("type", "file");
        nmap_button->setMaximumSize(QSize((desktop_width / 87), base_height));

        nmap_layout = new QHBoxLayout;
        nmap_layout->setMargin(0);
        nmap_layout->setSpacing(0);
        nmap_layout->addWidget(nmap_edit);
        nmap_layout->addWidget(nmap_button);

        match_combo = new QComboBox(Finder);
        match_combo->setView(new QListView());
        match_combo->view()->setFont(font);
        match_combo->setMinimumHeight(base_height);
        match_combo->setEditable(true);
        match_combo->lineEdit()->setReadOnly(true);
        match_combo->lineEdit()->setFont(font);
        match_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        match_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        match_combo->addItem("MATCH");
        match_combo->addItem("EXACT");
        match_combo->addItem("RELAX");
        for (int i = 0; i < match_combo->count(); ++i)
            match_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m1 = qobject_cast<QStandardItemModel*>(match_combo->model());
        QModelIndex i1 = m1->index(0, match_combo->modelColumn(), match_combo->rootModelIndex());
        QStandardItem *it1 = m1->itemFromIndex(i1);
        it1->setSelectable(false);

        vector_combo = new QComboBox(Finder);
        vector_combo->setView(new QListView());
        vector_combo->view()->setFont(font);
        vector_combo->setMinimumHeight(base_height);
        vector_combo->setEditable(true);
        vector_combo->lineEdit()->setReadOnly(true);
        vector_combo->lineEdit()->setFont(font);
        vector_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        vector_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        vector_combo->addItem("VECTOR");
        vector_combo->addItem("ANY");
        vector_combo->addItem("LOCAL");
        vector_combo->addItem("REMOTE");
        vector_combo->addItem("ADJACENT");
        vector_combo->addItem("PHYSICAL");
        for (int i = 0; i < vector_combo->count(); ++i)
            vector_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m2 = qobject_cast<QStandardItemModel*>(vector_combo->model());
        QModelIndex i2 = m2->index(0, vector_combo->modelColumn(), vector_combo->rootModelIndex());
        QStandardItem *it2 = m2->itemFromIndex(i2);
        it2->setSelectable(false);

        type_combo = new QComboBox(Finder);
        type_combo->setView(new QListView());
        type_combo->view()->setFont(font);
        type_combo->setMinimumHeight(base_height);
        type_combo->setEditable(true);
        type_combo->lineEdit()->setReadOnly(true);
        type_combo->lineEdit()->setFont(font);
        type_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        type_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        type_combo->addItem("TYPE");
        type_combo->addItem("CVE");
        type_combo->addItem("EXPLOITDB");
        type_combo->addItem("PACKETSTORM");
        type_combo->addItem("WPVDB");
        for (int i = 0; i < type_combo->count(); ++i)
            type_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m3 = qobject_cast<QStandardItemModel*>(type_combo->model());
        QModelIndex i3 = m3->index(0, type_combo->modelColumn(), type_combo->rootModelIndex());
        QStandardItem *it3 = m3->itemFromIndex(i3);
        it3->setSelectable(false);

        score_edit = new QLineEdit(Finder);
        score_edit->setFont(font);
        score_edit->setMaximumWidth(desktop_width / 29.5);
        score_edit->setMinimumHeight(base_height);
        score_edit->setAlignment(Qt::AlignCenter);
        score_edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        score_edit->setPlaceholderText("SCORE");
        score_edit->setToolTip("MIN-MAX");

        date_combo = new QComboBox(Finder);
        date_combo->setView(new QListView());
        date_combo->view()->setFont(font);
        date_combo->setMinimumHeight(base_height);
        date_combo->setEditable(true);
        date_combo->lineEdit()->setReadOnly(true);
        date_combo->lineEdit()->setFont(font);
        date_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        date_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        date_combo->addItem("DATE");
        date_combo->addItem("ANY");
        date_combo->addItem("10 DAYS");
        date_combo->addItem("1 MONTH");
        date_combo->addItem("6 MONTHS");
        date_combo->addItem("1 YEAR");
        for (int i = 0; i < date_combo->count(); ++i)
            date_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m4 = qobject_cast<QStandardItemModel*>(date_combo->model());
        QModelIndex i4 = m4->index(0, date_combo->modelColumn(), date_combo->rootModelIndex());
        QStandardItem *it4 = m4->itemFromIndex(i4);
        it4->setSelectable(false);

        order_combo = new QComboBox(Finder);
        order_combo->setView(new QListView());
        order_combo->view()->setFont(font);
        order_combo->setMinimumHeight(base_height);
        order_combo->setEditable(true);
        order_combo->lineEdit()->setReadOnly(true);
        order_combo->lineEdit()->setFont(font);
        order_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        order_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        order_combo->addItem("ORDER");
        order_combo->addItem("DATE");
        order_combo->addItem("SCORE");
        for (int i = 0; i < order_combo->count(); ++i)
            order_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m5 = qobject_cast<QStandardItemModel*>(order_combo->model());
        QModelIndex i5 = m5->index(0, order_combo->modelColumn(), order_combo->rootModelIndex());
        QStandardItem *it5 = m5->itemFromIndex(i5);
        it5->setSelectable(false);

        max_combo = new QComboBox(Finder);
        max_combo->setView(new QListView());
        max_combo->view()->setFont(font);
        max_combo->setMinimumWidth(desktop_width / 24.6);
        max_combo->setMinimumHeight(base_height);
        max_combo->setEditable(true);
        max_combo->lineEdit()->setReadOnly(true);
        max_combo->lineEdit()->setFont(font);
        max_combo->lineEdit()->setAlignment(Qt::AlignCenter);
        max_combo->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        max_combo->addItem("MAX");
        max_combo->addItem("1");
        max_combo->addItem("5");
        max_combo->addItem("10");
        max_combo->addItem("20");
        max_combo->addItem("50");
        max_combo->addItem("100");
        max_combo->addItem("500");
        for (int i = 0; i < max_combo->count(); ++i)
            max_combo->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        QStandardItemModel *m6 = qobject_cast<QStandardItemModel*>(max_combo->model());
        QModelIndex i6 = m6->index(0, max_combo->modelColumn(), max_combo->rootModelIndex());
        QStandardItem *it6 = m6->itemFromIndex(i6);
        it6->setSelectable(false);

        request_button = new QPushButton(QIcon(":/icon-find"), NULL, Finder);
        request_button->setIconSize(QSize(base_size, base_size));
        request_button->setFlat(true);

        counter_offset_label = new QLabel(Finder);
        counter_offset_label->setProperty("type", "border");
        counter_offset_label->setFont(font);
        counter_offset_label->setMinimumWidth(desktop_width / 25.6);
        counter_offset_label->setMinimumHeight(base_height);
        counter_offset_label->setAlignment(Qt::AlignCenter);
        counter_offset_label->setText("0");

        counter_total_label = new QLabel(Finder);
        counter_total_label->setProperty("type", "border");
        counter_total_label->setFont(font);
        counter_total_label->setMinimumWidth(desktop_width / 25.6);
        counter_total_label->setMinimumHeight(base_height);
        counter_total_label->setAlignment(Qt::AlignCenter);
        counter_total_label->setText("0");

        request_offset_button = new QPushButton(QIcon(":/icon-find-disabled"), NULL, Finder);
        request_offset_button->setIconSize(QSize(base_size, base_size));
        request_offset_button->setFlat(true);
        request_offset_button->setDisabled(true);

        layout = new QHBoxLayout(Finder);
        layout->setMargin(0);
        layout->setSpacing(base_space);
        layout->addWidget(id_edit);
        layout->addWidget(cve_edit);
        layout->addWidget(name_edit);
        layout->addWidget(version_edit);
        layout->addLayout(nmap_layout);
        layout->addWidget(match_combo);
        layout->addWidget(vector_combo);
        layout->addWidget(type_combo);
        layout->addWidget(score_edit);
        layout->addWidget(date_combo);
        layout->addWidget(order_combo);
        layout->addWidget(max_combo);
        layout->addWidget(request_button);
        layout->addWidget(counter_offset_label);
        layout->addSpacing(desktop_width / 480);
        layout->addWidget(counter_total_label);
        layout->addSpacing(desktop_width / 480);
        layout->addWidget(request_offset_button);

        Finder->setLayout(layout);
    }
};

class Ui_View
{
public:
    QWidget *scroll_widget;
    QScrollArea *scroll_area;
    QVBoxLayout *scroll_layout;
    QVBoxLayout *layout;

    void setupUi(QWidget *View)
    {
        int desktop_width = QApplication::desktop()->screenGeometry().width();
        int desktop_height = QApplication::desktop()->screenGeometry().height();
        int base_space = (desktop_width / 384);

        scroll_widget = new QWidget(View);

        scroll_area = new QScrollArea(View);
        scroll_area->setWidgetResizable(true);
        scroll_area->setFrameStyle(QFrame::NoFrame);
        scroll_area->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scroll_area->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

        scroll_layout = new QVBoxLayout;
        scroll_layout->setMargin(0);
        scroll_layout->setSpacing(base_space);
        scroll_layout->setAlignment(Qt::AlignTop);

        scroll_widget->setLayout(scroll_layout);
        scroll_area->setWidget(scroll_widget);

        layout = new QVBoxLayout(View);
        layout->setMargin(0);
        layout->setSpacing(base_space);
        layout->addWidget(scroll_area);

        View->setMinimumHeight(desktop_height / 1.125);
        View->setMaximumHeight(desktop_height / 1.125);
        View->setLayout(layout);
    }
};

class Ui_Bulletin
{
public:
    QLabel *number_label;
    QLabel *published_label;
    QLabel *title_label;
    QLabel *score_label;
    QLabel *description_label;
    QLabel *id_label;
    QLabel *cve_label;
    QLabel *cvss_label;
    QLabel *cpe_vendor_label;
    QLabel *cpe_product_label;
    QLabel *cpe_version_label;
    QLabel *href_label;
    QLabel *source_label;
    QLabel *source_line_label;
    QTextEdit *source_text;
    QPushButton *details_button;
    QPushButton *source_details_button;
    QPushButton *source_save_button;
    Highlighter *highlighter;
    QHBoxLayout *cpe_layout;
    QHBoxLayout *source_label_layout;
    QVBoxLayout *source_layout;
    QGridLayout *layout;

    void setupUi(QWidget *Bulletin)
    {
        int desktop_width = QApplication::desktop()->screenGeometry().width();
        int desktop_height = QApplication::desktop()->screenGeometry().height();
        int base_height = (desktop_height / 30.85);
        int base_size = (desktop_width / 160);
        int base_margin = (desktop_width / 240);
        int base_space = (desktop_width / 384);

        QFont font(":/font-default");
        font.setPointSize(desktop_width / 174.5);

        number_label = new QLabel(Bulletin);
        number_label->setProperty("type", "gray-dark-bg");
        number_label->setFont(font);
        number_label->setMinimumWidth(desktop_width / 25.6);
        number_label->setMinimumHeight(base_height);
        number_label->setAlignment(Qt::AlignCenter);

        published_label = new QLabel(Bulletin);
        published_label->setProperty("type", "gray-bg");
        published_label->setFont(font);
        published_label->setMinimumWidth(desktop_width / 16.5);
        published_label->setMinimumHeight(base_height);
        published_label->setAlignment(Qt::AlignCenter);

        title_label = new QLabel(Bulletin);
        title_label->setProperty("type", "gray-light-bg");
        title_label->setFont(font);
        title_label->setMinimumWidth(desktop_width / 9.51);
        title_label->setMinimumHeight(base_height);
        title_label->setMargin(base_margin);
        title_label->setTextInteractionFlags(Qt::TextSelectableByMouse);

        score_label = new QLabel(Bulletin);
        score_label->setProperty("type", "score-low");
        score_label->setFont(font);
        score_label->setMinimumWidth(desktop_width / 25.6);
        score_label->setMinimumHeight(base_height);
        score_label->setAlignment(Qt::AlignCenter);

        details_button = new QPushButton(QIcon(":/icon-more"), NULL, Bulletin);
        details_button->setIconSize(QSize(base_size, base_size));
        details_button->setFlat(true);

        font.setItalic(true);

        description_label = new QLabel(Bulletin);
        description_label->setProperty("type", "white-bg");
        description_label->setFont(font);
        description_label->setMinimumHeight(base_height);
        description_label->setMargin(base_margin);
        description_label->setWordWrap(true);
        description_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        description_label->setHidden(true);

        font.setItalic(false);

        id_label = new QLabel(Bulletin);
        id_label->setProperty("type", "white");
        id_label->setFont(font);
        id_label->setMargin(base_margin);
        id_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        id_label->setText("<span style=color:#998f46>ID</span><hr>");
        id_label->setHidden(true);

        cve_label = new QLabel(Bulletin);
        cve_label->setProperty("type", "white");
        cve_label->setFont(font);
        cve_label->setMargin(base_margin);
        cve_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        cve_label->setText("<span style=color:#998f46>CVE</span><hr>");
        cve_label->setHidden(true);

        cvss_label = new QLabel(Bulletin);
        cvss_label->setFont(font);
        cvss_label->setMargin(base_margin);
        cvss_label->setText("<span style=color:#998f46>CVSS</span><hr>");
        cvss_label->setHidden(true);

        font.setCapitalization(QFont::AllUppercase);

        cpe_vendor_label = new QLabel(Bulletin);
        cpe_vendor_label->setProperty("type", "white");
        cpe_vendor_label->setFont(font);
        cpe_vendor_label->setMargin(base_margin);
        cpe_vendor_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        cpe_vendor_label->setText("<span style=color:#998f46>VENDOR</span><hr>");
        cpe_vendor_label->setHidden(true);

        cpe_product_label = new QLabel(Bulletin);
        cpe_product_label->setProperty("type", "white");
        cpe_product_label->setFont(font);
        cpe_product_label->setMargin(base_margin);
        cpe_product_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        cpe_product_label->setText("<span style=color:#998f46>PRODUCT</span><hr>");
        cpe_product_label->setHidden(true);

        cpe_version_label = new QLabel(Bulletin);
        cpe_version_label->setProperty("type", "white");
        cpe_version_label->setFont(font);
        cpe_version_label->setMargin(base_margin);
        cpe_version_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        cpe_version_label->setText("<span style=color:#998f46>VERSION</span><hr>");
        cpe_version_label->setHidden(true);

        cpe_layout = new QHBoxLayout;
        cpe_layout->setMargin(0);
        cpe_layout->setSpacing(0);
        cpe_layout->addWidget(cpe_vendor_label);
        cpe_layout->addWidget(cpe_product_label);
        cpe_layout->addWidget(cpe_version_label);

        font.setCapitalization(QFont::MixedCase);

        href_label = new QLabel(Bulletin);
        href_label->setFont(font);
        href_label->setMargin(base_margin);
        href_label->setTextInteractionFlags(Qt::TextBrowserInteraction | Qt::TextSelectableByMouse);
        href_label->setOpenExternalLinks(true);
        href_label->setText("<span style=color:#998f46>REFERENCES</span><hr>");
        href_label->setHidden(true);

        source_label = new QLabel(Bulletin);
        source_label->setFont(font);
        source_label->setContentsMargins(0, base_margin, 0, 0);
        source_label->setText("<span style=color:#998f46>SOURCE</span>");
        source_label->setHidden(true);

        source_details_button = new QPushButton(QIcon(":/icon-source-more"), NULL, Bulletin);
        source_details_button->setIconSize(QSize(base_size, (desktop_height / 60)));
        source_details_button->setMinimumSize(QSize(base_size, (desktop_height / 60)));
        source_details_button->setFlat(true);
        source_details_button->setHidden(true);

        source_label_layout = new QHBoxLayout;
        source_label_layout->setMargin(0);
        source_label_layout->setSpacing(base_space);
        source_label_layout->addWidget(source_label);
        source_label_layout->addWidget(source_details_button);
        source_label_layout->addStretch();

        source_line_label = new QLabel(Bulletin);
        source_line_label->setFont(font);
        source_line_label->setText("<hr>");
        source_line_label->setHidden(true);

        source_text = new QTextEdit(Bulletin);
        source_text->setProperty("type", "source");
        source_text->setFont(font);
        source_text->setMinimumHeight(desktop_height / 1.155);
        source_text->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        source_text->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        source_text->setReadOnly(true);
        source_text->setHidden(true);

        highlighter = new Highlighter(source_text->document());

        source_save_button = new QPushButton(QIcon(":/icon-save"), NULL, source_text);
        source_save_button->setIconSize(QSize((desktop_width / 96), (desktop_width / 96)));
        source_save_button->setMaximumWidth(desktop_width / 96);
        source_save_button->move((desktop_width / 1.2590), base_space);
        source_save_button->setFlat(true);
        source_save_button->setToolTip("SAVE");

        source_layout = new QVBoxLayout;
        source_layout->setContentsMargins(base_margin, 0, base_margin, 0);
        source_layout->setSpacing(0);
        source_layout->addLayout(source_label_layout);
        source_layout->addWidget(source_line_label);
        source_layout->addWidget(source_text);

        layout = new QGridLayout(Bulletin);
        layout->setMargin(0);
        layout->setHorizontalSpacing(base_space);
        layout->setVerticalSpacing(desktop_height / 72);
        layout->setColumnStretch(2, 1);
        layout->addWidget(number_label, 0, 0, 1, 1);
        layout->addWidget(published_label, 0, 1, 1, 1);
        layout->addWidget(title_label, 0, 2, 1, 1);
        layout->addWidget(score_label, 0, 3, 1, 1);
        layout->addWidget(details_button, 0, 4, 1, 4);
        layout->addWidget(description_label, 1, 2, 1, 1);
        layout->addWidget(id_label, 2, 2, 1, 1);
        layout->addWidget(cve_label, 3, 2, 1, 1);
        layout->addWidget(cvss_label, 4, 2, 1, 1);
        layout->addLayout(cpe_layout, 5, 2, 1, 1);
        layout->addWidget(href_label, 6, 2, 1, 1);
        layout->addLayout(source_layout, 7, 2, 1, 1);

        Bulletin->setMinimumWidth(desktop_width / 1.0105);
        Bulletin->setMaximumWidth(desktop_width / 1.0105);
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

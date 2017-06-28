#ifndef UI_H
#define UI_H

#include "highlighter.h"

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QTextEdit>
#include <QPushButton>
#include <QListView>
#include <QScrollArea>
#include <QToolTip>
#include <QVBoxLayout>
#include <QGridLayout>

#include <QApplication>

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
    QLabel *score_label;
    QLabel *cve_label;
    QLabel *type_label;
    QLabel *date_label;
    QLabel *order_label;
    QLabel *max_label;
    QLineEdit *name_lineedit;
    QLineEdit *version_lineedit;
    QLineEdit *score_lineedit;
    QLineEdit *cve_lineedit;
    QComboBox *type_combo;
    QComboBox *date_combo;
    QComboBox *order_combo;
    QComboBox *max_combo;
    QPushButton *find_button;
    QGridLayout *layout;

    void setupUi(QWidget *Finder)
    {
        QFont font(":/font-default");
        font.setPointSize(11); // TODO: PERCENT
        font.setCapitalization(QFont::AllUppercase);

        name_label = new QLabel(Finder);
        name_label->setProperty("type", "header");
        name_label->setFont(font);
        name_label->setContentsMargins(8, 0, 0, 0); // TODO: PERCENT
        name_label->setText("NAME");

        name_lineedit = new QLineEdit(Finder);
        name_lineedit->setFont(font);
        name_lineedit->setMinimumHeight(30); // TODO: PERCENT
        name_lineedit->setTextMargins(8, 0, 0, 0); // TODO: PERCENT
        name_lineedit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

        version_label = new QLabel(Finder);
        version_label->setProperty("type", "header");
        version_label->setFont(font);
        version_label->setContentsMargins(8, 0, 0, 0); // TODO: PERCENT
        version_label->setText("VERSION");

        version_lineedit = new QLineEdit(Finder);
        version_lineedit->setFont(font);
        version_lineedit->setMinimumHeight(30); // TODO: PERCENT
        version_lineedit->setTextMargins(8, 0, 0, 0); // TODO: PERCENT
        version_lineedit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        version_lineedit->setPlaceholderText("0.0.*");

        score_label = new QLabel(Finder);
        score_label->setProperty("type", "header");
        score_label->setFont(font);
        score_label->setContentsMargins(8, 0, 0, 0); // TODO: PERCENT
        score_label->setText("SCORE");

        score_lineedit = new QLineEdit(Finder);
        score_lineedit->setFont(font);
        score_lineedit->setMinimumHeight(30); // TODO: PERCENT
        score_lineedit->setTextMargins(8, 0, 0, 0); // TODO: PERCENT
        score_lineedit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        score_lineedit->setPlaceholderText("MIN-MAX");

        cve_label = new QLabel(Finder);
        cve_label->setProperty("type", "header");
        cve_label->setFont(font);
        cve_label->setContentsMargins(8, 0, 0, 0); // TODO: PERCENT
        cve_label->setText("CVE");

        cve_lineedit = new QLineEdit(Finder);
        cve_lineedit->setFont(font);
        cve_lineedit->setMinimumHeight(30); // TODO: PERCENT
        cve_lineedit->setTextMargins(8, 0, 0, 0); // TODO: PERCENT
        cve_lineedit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        cve_lineedit->setPlaceholderText("YYYY-0000");

        type_label = new QLabel(Finder);
        type_label->setProperty("type", "header");
        type_label->setFont(font);
        type_label->setContentsMargins(8, 0, 0, 0);
        type_label->setText("TYPE");

        type_combo = new QComboBox(Finder);
        type_combo->setFont(font);
        type_combo->setMinimumHeight(29); // TODO: PERCENT
        type_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        type_combo->setView(new QListView());
        type_combo->addItem("cve");
        type_combo->addItem("exploitdb");

        date_label = new QLabel(Finder);
        date_label->setProperty("type", "header");
        date_label->setFont(font);
        date_label->setContentsMargins(8, 0, 0, 0); // TODO: PERCENT
        date_label->setText("DATE");

        date_combo = new QComboBox(Finder);
        date_combo->setFont(font);
        date_combo->setMinimumHeight(29); // TODO: PERCENT
        date_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        date_combo->setView(new QListView());
        date_combo->addItem("all");
        date_combo->addItem("last 10 days");
        date_combo->addItem("last month");
        date_combo->addItem("last 6 month");
        date_combo->addItem("last year");

        order_label = new QLabel(Finder);
        order_label->setProperty("type", "header");
        order_label->setFont(font);
        order_label->setContentsMargins(8, 0, 0, 0); // TODO: PERCENT
        order_label->setText("ORDER");

        order_combo = new QComboBox(Finder);
        order_combo->setFont(font);
        order_combo->setMinimumHeight(29); // TODO: PERCENT
        order_combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        order_combo->setView(new QListView());
        order_combo->addItem("date");
        order_combo->addItem("score");

        max_label = new QLabel(Finder);
        max_label->setProperty("type", "header");
        max_label->setFont(font);
        max_label->setContentsMargins(8, 0, 0, 0);
        max_label->setText("MAX");

        max_combo = new QComboBox(Finder);
        max_combo->setFont(font);
        max_combo->setMinimumHeight(29); // TODO: PERCENT
        max_combo->setView(new QListView());
        max_combo->addItem("1");
        max_combo->addItem("5");
        max_combo->addItem("10");
        max_combo->addItem("20");
        max_combo->addItem("50");
        max_combo->addItem("100");
        max_combo->addItem("500");
        max_combo->setCurrentIndex(1);

        find_button = new QPushButton("→", Finder);
        find_button->setFont(font);
        find_button->setMinimumHeight(30); // TODO: PERCENT

        layout = new QGridLayout(Finder);
        layout->setMargin(0);
        layout->setHorizontalSpacing(3); // TODO: PERCENT
        layout->setVerticalSpacing(1);
        layout->addWidget(name_label, 0, 0, 1, 1);
        layout->addWidget(name_lineedit, 1, 0, 1, 1);
        layout->addWidget(version_label, 0, 1, 1, 1);
        layout->addWidget(version_lineedit, 1, 1, 1, 1);
        layout->addWidget(score_label, 0, 2, 1, 1);
        layout->addWidget(score_lineedit, 1, 2, 1, 1);
        layout->addWidget(cve_label, 0, 3, 1, 1);
        layout->addWidget(cve_lineedit, 1, 3, 1, 1);
        layout->addWidget(type_label, 0, 4, 1, 1);
        layout->addWidget(type_combo, 1, 4, 1, 1);
        layout->addWidget(date_label, 0, 5, 1, 1);
        layout->addWidget(date_combo, 1, 5, 1, 1);
        layout->addWidget(order_label, 0, 6, 1, 1);
        layout->addWidget(order_combo, 1, 6, 1, 1);
        layout->addWidget(max_label, 0, 7, 1, 1);
        layout->addWidget(max_combo, 1, 7, 1, 1);
        layout->addWidget(find_button, 1, 8, 1, 1);

        Finder->setLayout(layout);
    }
};

class Ui_View
{
public:
    QLabel *counter_label;
    QPushButton *request_button;
    QWidget *widget;
    QScrollArea *scrollarea;
    QVBoxLayout *layout;

    void setupUi(QWidget *View)
    {
        QFont font(":/font-default");
        font.setPointSize(11); // TODO: PERCENT

        counter_label = new QLabel(View);
        counter_label->setProperty("type", "header");
        counter_label->setFont(font);
        counter_label->setMinimumHeight(30); // TODO: PERCENT
        counter_label->setContentsMargins(8, 0, 8, 0); // TODO: PERCENT
        counter_label->hide();

        request_button = new QPushButton("→", View);
        request_button->setFont(font);
        request_button->setMinimumHeight(30); // TODO: PERCENT
        request_button->hide();

        widget = new QWidget(View);

        scrollarea = new QScrollArea(View);
        scrollarea->setWidgetResizable(true);
        scrollarea->setFrameStyle(QFrame::NoFrame);
        scrollarea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scrollarea->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

        layout = new QVBoxLayout(View);
        layout->setMargin(0);
        layout->setSpacing(5); // TODO: PERCENT
        layout->setAlignment(Qt::AlignTop);
        layout->addWidget(counter_label);
        layout->addWidget(request_button);

        widget->setLayout(layout);
        scrollarea->setWidget(widget);

        View->setLayout(layout);
    }
};

class Ui_Element
{
public:
    QLabel *published_label;
    QLabel *title_label;
    QLabel *score_label;
    QLabel *description_label;
    QLabel *id_label;
    QTextEdit *sourcedata_textedit;
    QPushButton *details_button;
    QPushButton *save_button;
    Highlighter *highlighter;
    QGridLayout *layout;

    void setupUi(QWidget *Element)
    {
        QFont font(":/font-default");
        font.setPointSize(11); // TODO: PERCENT

        published_label = new QLabel(Element);
        published_label->setProperty("type", "gray");
        published_label->setFont(font);
        published_label->setMinimumHeight(30); // TODO: PERCENT
        published_label->setContentsMargins(8, 0, 8, 0); // TODO: PERCENT
        published_label->setAlignment(Qt::AlignCenter);

        title_label = new QLabel(Element);
        title_label->setProperty("type", "title");
        title_label->setFont(font);
        title_label->setMinimumHeight(30); // TODO: PERCENT
        title_label->setContentsMargins(8, 0, 8, 0); // TODO: PERCENT
        title_label->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

        score_label = new QLabel(Element);
        score_label->setProperty("type", "gray");
        score_label->setFont(font);
        score_label->setMinimumWidth(42); // TODO: PERCENT
        score_label->setMinimumHeight(30); // TODO: PERCENT
        score_label->setAlignment(Qt::AlignCenter);

        details_button = new QPushButton("+", Element);
        details_button->setFont(font);
        details_button->setMinimumHeight(30); // TODO: PERCENT

        description_label = new QLabel(Element);
        description_label->setProperty("type", "gray-light");
        description_label->setFont(font);
        description_label->setMinimumHeight(30); // TODO: PERCENT
        description_label->setContentsMargins(8, 8, 8, 8); // TODO: PERCENT
        description_label->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        description_label->setWordWrap(true);
        description_label->setHidden(true);

        id_label = new QLabel(Element);
        id_label->setProperty("type", "gray-light");
        id_label->setFont(font);
        id_label->setMinimumHeight(30); // TODO: PERCENT
        id_label->setContentsMargins(8, 0, 8, 0); // TODO: PERCENT
        id_label->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        id_label->setHidden(true);

        sourcedata_textedit = new QTextEdit(Element);
        sourcedata_textedit->setProperty("type", "source-data");
        sourcedata_textedit->setFont(font);
        sourcedata_textedit->setMinimumHeight(800);//
        sourcedata_textedit->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        sourcedata_textedit->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        sourcedata_textedit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sourcedata_textedit->setHidden(true);

        highlighter = new Highlighter(sourcedata_textedit->document());

        save_button = new QPushButton("↓", Element);
        save_button->setFont(font);
        save_button->setMinimumHeight(30); // TODO: PERCENT
        save_button->setHidden(true);

        layout = new QGridLayout(Element);
        layout->setMargin(0);
        layout->setHorizontalSpacing(5); // TODO: PERCENT
        layout->setVerticalSpacing(5); // TODO: PERCENT
        layout->setColumnStretch(1, 1);
        layout->addWidget(published_label, 0, 0, 1, 1);
        layout->addWidget(title_label, 0, 1, 1, 1);
        layout->addWidget(score_label, 0, 2, 1, 1);
        layout->addWidget(details_button, 0, 3, 1, 3);
        layout->addWidget(description_label, 1, 1, 1, 1);
        layout->addWidget(id_label, 2, 1, 1, 1);
        layout->addWidget(sourcedata_textedit, 3, 1, 1, 1);
        layout->addWidget(save_button, 1, 3, 1, 3);

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

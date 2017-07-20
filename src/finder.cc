#include "finder.h"

Finder::Finder(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Finder)
{
    ui->setupUi(this);
    QObject::connect(ui->combo_match,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->combo_match->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->combo_vector,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->combo_vector->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->combo_type,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->combo_type->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->combo_date,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->combo_date->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->combo_order,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->combo_order->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->combo_max,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->combo_max->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->edit_name, &QLineEdit::returnPressed, [&] { request(); });
    QObject::connect(ui->edit_version, &QLineEdit::returnPressed, [&] { request(); });
    QObject::connect(ui->edit_cve, &QLineEdit::returnPressed, [&] { request(); });
    QObject::connect(ui->edit_score, &QLineEdit::returnPressed, [&] { request(); });
    QObject::connect(ui->button_request, &QPushButton::pressed, [&] { request(); });
}

Finder::~Finder()
{
    delete ui;
}

void Finder::request(bool has_offset)
{
    if (!has_offset) {
        offset = 0;
        set_query();
        set_vector();
        set_type();
        set_score();
        set_date();
        set_order();
        set_max();
        req = "GET /api/v3/search/lucene/?query=" +
              query +
              " cvss.vector:" + vector +
              " type:" + type +
              " cvss.score:" + score +
              " " + date +
              " sort:" + order +
              "&size=" + max +
              " HTTP/1.1\r\n"
              "Host:vulners.com\r\n"
              "Connection:Keep-Alive\r\n\r\n";
    } else {
        offset += std::stoi(max);
        req = "GET /api/v3/search/lucene/?query=" +
              query +
              " cvss.vector:" + vector +
              " type:" + type +
              " cvss.score:" + score +
              " " + date +
              " sort:" + order +
              "&size=" + max +
              "&skip=" + std::to_string(offset) +
              " HTTP/1.1\r\n"
              "Host:vulners.com\r\n"
              "Connection:Keep-Alive\r\n\r\n";
    }

    emit request_signal(req, std::stoi(max));
}

void Finder::set_query()
{
    if (ui->edit_cve->text() != "") {
        query = "cvelist:" + ui->edit_cve->text().toStdString();
    } else if (ui->edit_name->text() != "") {
        if ((ui->combo_match->currentText() == "MATCH") ||
            (ui->combo_match->currentText() == "EXACT")) {
            if ((ui->combo_type->currentText() == "TYPE") ||
                (ui->combo_type->currentText() == "CVE")) {
                if (ui->edit_version->text() != "")
                    query = "cpe:*" +
                            ui->edit_name->text().toStdString() +
                            "*\"" + ui->edit_version->text().toStdString() + "\"";
                else
                    query = "cpe:*" +
                            ui->edit_name->text().toStdString() + "*";
            } else if ((ui->combo_type->currentText() == "EXPLOITDB") ||
                       (ui->combo_type->currentText() == "WORDPRESSDB")) {
                query = "description:\"" +
                        ui->edit_name->text().toStdString() +
                        " " + ui->edit_version->text().toStdString() + "\"";
            } else {
                query = "title:\"" +
                        ui->edit_name->text().toStdString() +
                        " " + ui->edit_version->text().toStdString() + "\"";
            }
        } else {
            if (ui->combo_type->currentText() == "CVE") {
                query = "cpe:*" +
                        ui->edit_name->text().toStdString() +
                        " " + ui->edit_version->text().toStdString() + "*";
            } else if ((ui->combo_type->currentText() == "EXPLOITDB") ||
                       (ui->combo_type->currentText() == "WORDPRESSDB")) {
                query = "\"" + ui->edit_name->text().toStdString() +
                        " " + ui->edit_version->text().toStdString() + "\"";
            } else {
                query = ui->edit_name->text().toStdString() +
                        " " + ui->edit_version->text().toStdString();
            }
        }
    } else {
        query = "";
    }
}

void Finder::set_vector()
{
    if ((ui->combo_vector->currentText() == "VECTOR") ||
        (ui->combo_vector->currentText() == "ANY"))
        vector = "*";
    else if (ui->combo_vector->currentText() == "REMOTE")
        vector = "\"AV:NETWORK\"";
    else
        vector = "\"AV:" + ui->combo_vector->currentText().toStdString() + "\"";
}

void Finder::set_type()
{
    if ((ui->combo_type->currentText() == "TYPE") ||
        (ui->combo_type->currentText() == "CVE"))
        type = "cve";
    else if (ui->combo_type->currentText() == "WORDPRESSDB")
        type = "wpvulndb";
    else
        type = ui->combo_type->currentText().toLower().toStdString();
}

void Finder::set_score()
{
    if (ui->edit_score->text() != "") {
        std::size_t n;
        score = ui->edit_score->text().toStdString();
        if ((n = score.std::string::find("-")) != std::string::npos)
            score = "[" + score.std::string::replace(n, 1, " TO ") + "]";
    } else {
        score = "*";
    }
}

void Finder::set_date()
{
    if ((ui->combo_date->currentText() == "DATE") ||
        (ui->combo_date->currentText() == "ANY"))
        date = "";
    else
        date = ui->combo_date->currentText().toLower().toStdString();
}

void Finder::set_order()
{
    if ((ui->combo_order->currentText() == "ORDER") ||
        (ui->combo_order->currentText() == "DATE"))
        order = "published";
    else
        order = "cvss.score";
}

void Finder::set_max()
{
    if (ui->combo_max->currentText() == "MAX")
        max = "20";
    else
        max = ui->combo_max->currentText().toStdString();
}

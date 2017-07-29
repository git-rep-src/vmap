#include "finder.h"

#include <libxml++/libxml++.h>

#include <QFileDialog>

#include <algorithm>

Finder::Finder(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Finder),
    is_blocked(false),
    has_error(false),
    offset(0),
    last_dir("")
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
    QObject::connect(ui->edit_id, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->edit_cve, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->edit_nmap, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->button_nmap, &QPushButton::pressed, [&] { open_file(); });
    QObject::connect(ui->edit_name, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->edit_version, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->edit_score, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->button_request, &QPushButton::pressed, [&] { build_request(); });
}

Finder::~Finder()
{
    delete ui;
}

void Finder::build_request(bool has_offset)
{
    is_blocked = false;

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

    if (!has_error)
        emit request_signal(req, ui->edit_name->text().toStdString(),
                            ui->edit_version->text().toStdString(), std::stoi(max));
}

void Finder::set_query()
{
    has_error = false;

    if (ui->edit_id->text() != "") {
        query = "id:\"" +
                ui->edit_id->text().toStdString() +
                "\"";
        is_blocked = true;
    } else if (ui->edit_cve->text() != "") {
        if (!ui->edit_cve->text().contains("CVE-"))
            query = "cvelist:CVE-" + ui->edit_cve->text().toStdString();
        else
            query = "cvelist:" + ui->edit_cve->text().toStdString();
        is_blocked = true;
    } else if (ui->edit_nmap->text() != "") {
        std::vector<std::string> terms;
        if (xml(&terms)) {
            std::string buf;
            for (size_t i = 0; i < terms.size(); i++) {
                buf = buf + "(" + terms[i] + ")";
                if (i != (terms.size() - 1))
                    buf.append(" OR ");
            }
            query = "description:(" + buf + ")";
        } else {
            has_error = true;
            emit status_signal("<span style=color:#5c181b>NMAP FILE ERROR</span>");
        }
    } else if ((ui->edit_name->text() != "") ||
               (ui->edit_version->text() != "")) {
        if ((ui->combo_match->currentText() == "MATCH") ||
            (ui->combo_match->currentText() == "EXACT")) {
            if (ui->combo_type->currentText() == "PACKETSTORM")
                query = "title:(\"" +
                        ui->edit_name->text().toStdString() +
                        "\" AND \"" +
                        ui->edit_version->text().toStdString() +
                        "\")";
            else
                query = "description:(\"" +
                        ui->edit_name->text().toStdString() +
                        "\" AND \"" +
                        ui->edit_version->text().toStdString() +
                        "\")";
        } else {
            if (ui->combo_type->currentText() == "PACKETSTORM")
                query = "title:" +
                        ui->edit_name->text().toStdString() +
                        " " + ui->edit_version->text().toStdString();
            else
                query = "description:" +
                        ui->edit_name->text().toStdString() +
                        " " +
                        ui->edit_version->text().toStdString();
        }
    } else {
        query = "";
    }
}

void Finder::set_vector()
{
    if ((ui->combo_vector->currentText() == "VECTOR") ||
        (ui->combo_vector->currentText() == "ANY") ||
        is_blocked)
        vector = "*";
    else if (ui->combo_vector->currentText() == "REMOTE")
        vector = "\"AV:NETWORK\"";
    else
        vector = "\"AV:" + ui->combo_vector->currentText().toStdString() + "\"";
}

void Finder::set_type()
{
    if (is_blocked)
        type = "*";
    else if ((ui->combo_type->currentText() == "TYPE") ||
             (ui->combo_type->currentText() == "CVE"))
        type = "cve";
    else if (ui->combo_type->currentText() == "WORDPRESSDB")
        type = "wpvulndb";
    else
        type = ui->combo_type->currentText().toLower().toStdString();
}

void Finder::set_score()
{
    if ((ui->edit_score->text() != "") && !is_blocked) {
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
        (ui->combo_date->currentText() == "ANY") ||
        is_blocked)
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

void Finder::open_file()
{
    QString file_path = QFileDialog::getOpenFileName(this, "", last_dir,
                                                     tr("XML Files") +
                                                     " (*.xml);;" +
                                                     tr("All Files") +
                                                     " (*.*)",
                                                     NULL, QFileDialog::ReadOnly);
    if (file_path != "") {
        last_dir = file_path.left(file_path.lastIndexOf('/'));
        ui->edit_nmap->setText(file_path);
    }
}


bool Finder::xml(std::vector<std::string> *terms)
{
    std::string buf;
    const std::vector<std::string> xpaths =
    {
        "/nmaprun/host/ports/port/state",
        "/nmaprun/host/ports/port/service"
    };
    const std::vector<std::string> xattributes =
    {
        "state",
        "product",
        "version"
    };

    try {
        xmlpp::DomParser parser;
        parser.parse_file(ui->edit_nmap->text().toStdString());
        xmlpp::Node *root = parser.get_document()->get_root_node();

        xmlpp::Node::NodeSet node;
        xmlpp::Element *element;
        xmlpp::Attribute *attribute;

        node = root->find(xpaths[0]);

        if (node.size() == 0) {
            return false;
        } else {
            for (size_t i = 0; i < node.size(); i++) {
                node = root->find(xpaths[0]);
                element = (xmlpp::Element *)node.at(i);
                attribute = element->get_attribute(xattributes[0]);
                if (attribute) {
                    if (attribute->get_value() == "open") {
                        node = root->find(xpaths[1]);
                        element = (xmlpp::Element *)node.at(i);
                        for (size_t ii = 1; ii <= 2; ii++) {
                            attribute = element->get_attribute(xattributes[ii]);
                            if (attribute)
                                buf =  buf + std::string(" ") + attribute->get_value();
                        }
                        if (buf != "") {
                            bool has_term = false;
                            std::replace(buf.begin(), buf.end(), '/', ' ');
                            std::transform(buf.begin(), buf.end(), buf.begin(), ::tolower);
                            for (size_t iii = 0; iii < terms->size(); iii++) {
                                if ((*terms)[iii].std::string::find(buf) != std::string::npos)
                                    has_term = true;
                            }
                            if (!has_term)
                                terms->push_back(buf);
                        }
                        buf.clear();
                    }
                }
            }
        }
    } catch (...) {
        return false;
    }

    return true;
}

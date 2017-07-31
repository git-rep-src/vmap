#include "finder.h"

#include <libxml++/libxml++.h>

#include <QFileDialog>

Finder::Finder(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Finder),
    is_blocked(false),
    has_error(false),
    last_dir("")
{
    ui->setupUi(this);
    QObject::connect(ui->match_combo,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->match_combo->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->vector_combo,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->vector_combo->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->type_combo,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->type_combo->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->date_combo,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->date_combo->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->order_combo,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->order_combo->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->max_combo,
                     static_cast<void(QComboBox::*)(const QString&)>(&QComboBox::currentTextChanged), [&] {
        ui->max_combo->setStyleSheet("QComboBox { color: white; background-color: rgb(30, 33, 37); }");
    });
    QObject::connect(ui->id_edit, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->cve_edit, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->name_edit, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->version_edit, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->nmap_edit, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->nmap_button, &QPushButton::pressed, [&] { open_file(); });
    QObject::connect(ui->score_edit, &QLineEdit::returnPressed, [&] { build_request(); });
    QObject::connect(ui->request_button, &QPushButton::pressed, [&] { build_request(); });
    QObject::connect(ui->request_offset_button, &QPushButton::pressed, [&] { build_request(true); });
}

Finder::~Finder()
{
    delete ui;
}

void Finder::build_request(bool has_offset)
{
    is_blocked = false;

    if (!has_offset) {
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
        req = "GET /api/v3/search/lucene/?query=" +
              query +
              " cvss.vector:" + vector +
              " type:" + type +
              " cvss.score:" + score +
              " " + date +
              " sort:" + order +
              "&size=" + max +
              "&skip=" + ui->counter_offset_label->text().toStdString() +
              " HTTP/1.1\r\n"
              "Host:vulners.com\r\n"
              "Connection:Keep-Alive\r\n\r\n";
    }

    if (!has_error)
        emit request_signal(req, ui->name_edit->text().toStdString(),
                            ui->version_edit->text().toStdString(), std::stoi(max),
                            has_offset);
}

void Finder::set_query()
{
    has_error = false;

    if (ui->id_edit->text() != "") {
        query = "id:\"" +
                ui->id_edit->text().toStdString() +
                "\"";
        is_blocked = true;
    } else if (ui->cve_edit->text() != "") {
        if (!ui->cve_edit->text().contains("CVE-"))
            query = "cvelist:CVE-" + ui->cve_edit->text().toStdString();
        else
            query = "cvelist:" + ui->cve_edit->text().toStdString();
        is_blocked = true;
    } else if (ui->nmap_edit->text() != "") {
        std::vector<std::string> terms;
        if (xml(&terms)) {
            std::string buf;
            for (size_t i = 0; i < terms.size(); i++) {
                buf = buf + "(" + terms[i] + ")";
                if (i != (terms.size() - 1))
                    buf.append(" OR ");
            }
            if (ui->type_combo->currentText() == "PACKETSTORM")
                query = "title:(" + buf + ")";
            else
                query = "description:(" + buf + ")";
        } else {
            has_error = true;
            emit status_signal("<span style=color:#5c181b>NMAP FILE ERROR</span>");
        }
    } else if ((ui->name_edit->text() != "") ||
               (ui->version_edit->text() != "")) {
        if ((ui->match_combo->currentText() == "MATCH") ||
            (ui->match_combo->currentText() == "EXACT")) {
            if (ui->type_combo->currentText() == "PACKETSTORM")
                query = "title:(\"" +
                        ui->name_edit->text().toStdString() +
                        "\" AND \"" +
                        ui->version_edit->text().toStdString() +
                        "\")";
            else
                query = "description:(\"" +
                        ui->name_edit->text().toStdString() +
                        "\" AND \"" +
                        ui->version_edit->text().toStdString() +
                        "\")";
        } else {
            if (ui->type_combo->currentText() == "PACKETSTORM")
                query = "title:" +
                        ui->name_edit->text().toStdString() +
                        " " +
                        ui->version_edit->text().toStdString();
            else
                query = "description:" +
                        ui->name_edit->text().toStdString() +
                        " " +
                        ui->version_edit->text().toStdString();
        }
    } else {
        query = "";
    }
}

void Finder::set_vector()
{
    if ((ui->vector_combo->currentText() == "VECTOR") ||
        (ui->vector_combo->currentText() == "ANY") ||
        is_blocked)
        vector = "*";
    else if (ui->vector_combo->currentText() == "REMOTE")
        vector = "\"AV:NETWORK\"";
    else
        vector = "\"AV:" + ui->vector_combo->currentText().toStdString() + "\"";
}

void Finder::set_type()
{
    if (is_blocked)
        type = "*";
    else if ((ui->type_combo->currentText() == "TYPE") ||
             (ui->type_combo->currentText() == "CVE"))
        type = "cve";
    else if (ui->type_combo->currentText() == "WPVDB")
        type = "wpvulndb";
    else
        type = ui->type_combo->currentText().toLower().toStdString();
}

void Finder::set_score()
{
    if ((ui->score_edit->text() != "") && !is_blocked) {
        std::size_t n;
        score = ui->score_edit->text().toStdString();
        if ((n = score.std::string::find("-")) != std::string::npos)
            score = "[" + score.std::string::replace(n, 1, " TO ") + "]";
    } else {
        score = "*";
    }
}

void Finder::set_date()
{
    if ((ui->date_combo->currentText() == "DATE") ||
        (ui->date_combo->currentText() == "ANY") ||
        is_blocked)
        date = "";
    else if (ui->date_combo->currentText() == "10 DAYS")
        date = "last 10 days";
    else if (ui->date_combo->currentText() == "1 MONTH")
        date = "last month";
    else if (ui->date_combo->currentText() == "6 MONTHS")
        date = "last 6 month";
    else
        date = "last year";
}

void Finder::set_order()
{
    if ((ui->order_combo->currentText() == "ORDER") ||
        (ui->order_combo->currentText() == "DATE"))
        order = "published";
    else
        order = "cvss.score";
}

void Finder::set_max()
{
    if (ui->max_combo->currentText() == "MAX")
        max = "20";
    else
        max = ui->max_combo->currentText().toStdString();
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
        ui->nmap_edit->setText(file_path);
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
        parser.parse_file(ui->nmap_edit->text().toStdString());
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

void Finder::set_counter(int offset, int n_total)
{
    ui->counter_offset_label->setText(QString::number(offset));
    ui->counter_total_label->setText(QString::number(n_total));
    if (offset != n_total) {
        ui->request_offset_button->setIcon(QIcon(":/icon-find"));
        ui->request_offset_button->setEnabled(true);
    } else {
        ui->request_offset_button->setIcon(QIcon(":/icon-find-disabled"));
        ui->request_offset_button->setDisabled(true);
    }
}

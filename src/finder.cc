#include "finder.h"

Finder::Finder(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Finder)
{
    ui->setupUi(this);
    QObject::connect(ui->find_button, &QPushButton::pressed, [&] { build_request(); });
}

Finder::~Finder()
{
    delete ui;
}

void Finder::build_request(bool has_offset)
{
    if (!has_offset) {
        if (ui->cve_lineedit->text() != "") {
            req = "GET /api/v3/search/lucene/?query="
                  " cvelist:CVE-" + ui->cve_lineedit->text().toStdString() +
                  " type:cve"
                  " HTTP/1.1\r\nHost: vulners.com\r\n\r\n";
        } else {
            name = ui->name_lineedit->text().toStdString();
            version = ui->version_lineedit->text().toStdString();
            if (ui->score_lineedit->text() != "")
                score = "[" + ui->score_lineedit->text().replace("-", " TO ").toStdString() + "]";
            else
                score = "*";
            type = ui->type_combo->currentText().toStdString();
            if (ui->date_combo->currentText() != "all")
                date = ui->date_combo->currentText().toStdString();
            else
                date = "";
            if (ui->order_combo->currentText() == "date")
                order = "published";
            else
                order = "cvss.score";
            max = ui->max_combo->currentText().toStdString();
            offset = 0;
            req = "GET /api/v3/search/lucene/?query="
                  + name +
                  " " + version +
                  " cvss.score:" + score +
                  " type:" + type +
                  " " + date +
                  " sort:" + order +
                  "&size=" + max +
                  " HTTP/1.1\r\nHost: vulners.com\r\n\r\n";
        }
    } else {
        offset += std::stoi(max);
        req = "GET /api/v3/search/lucene/?query="
              + name +
              " " + version +
              " cvss.score:" + score +
              " type:" + type +
              " " + date +
              " sort:" + order +
              "&size=" + max +
              "&skip=" + std::to_string(offset) +
              " HTTP/1.1\r\nHost: vulners.com\r\n\r\n";
    }

    emit send_request_signal(req);
}

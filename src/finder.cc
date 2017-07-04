#include "finder.h"

Finder::Finder(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Finder)
{
    ui->setupUi(this);
    QObject::connect(ui->request_button, &QPushButton::pressed, [&] { build_request(); });
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
                  " HTTP/1.1\r\n"
                  "Host:vulners.com\r\n"
                  "Connection:Keep-Alive\r\n\r\n";
        } else {
            if (ui->match_combo->currentText() == "EXACT") {
                if (ui->type_combo->currentText() == "CVE") {
                    if (ui->version_lineedit->text() != "")
                        query = " cpe:*" +
                                ui->name_lineedit->text().toStdString() +
                                "*\"" + ui->version_lineedit->text().toStdString() + "\"";
                    else
                        query = " cpe:*" +
                                ui->name_lineedit->text().toStdString() + "*";
                } else {
                    query = " description:\"" +
                            ui->name_lineedit->text().toStdString() +
                            " " + ui->version_lineedit->text().toStdString() + "\"";
                }
            } else {
                if (ui->type_combo->currentText() == "CVE") {
                    query = " cpe:*" +
                            ui->name_lineedit->text().toStdString() +
                            " " + ui->version_lineedit->text().toStdString() + "*";
                } else {
                    query = "\"" + ui->name_lineedit->text().toStdString() +
                            " " + ui->version_lineedit->text().toStdString() + "\"";
                }
            }

            if (ui->type_combo->currentText() == "CVE")
                type = "cve";
            else
                type = "exploitdb";
            if (ui->score_lineedit->text() != "")
                score = "[" + ui->score_lineedit->text().replace("-", " TO ").toStdString() + "]";
            else
                score = "*";
            if (ui->date_combo->currentText() != "ALL")
                date = ui->date_combo->currentText().toLower().toStdString();
            else
                date = "";
            if (ui->order_combo->currentText() == "DATE")
                order = "published";
            else
                order = "cvss.score";
            max = ui->max_combo->currentText().toStdString();
            offset = 0;
            req = "GET /api/v3/search/lucene/?query=" +
                  query +
                  " type:" + type +
                  " cvss.score:" + score +
                  " " + date +
                  " sort:" + order +
                  "&size=" + max +
                  " HTTP/1.1\r\n"
                  "Host:vulners.com\r\n"
                  "Connection:Keep-Alive\r\n\r\n";
        }
    } else {
        offset += std::stoi(max);
        req = "GET /api/v3/search/lucene/?query=" +
              query +
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

    emit send_request_signal(req, std::stoi(max));
}
// (affectedSoftware.name:"firefox" OR affectedPackage.packageName:"firefox" OR cpe:*firefox*"45") type:cve
// AND affectedSoftware.version:
// type:packetstorm

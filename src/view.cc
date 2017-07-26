#include "view.h"

#include "json.cc"

#include <vector>

View::View(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::View),
    has_offset(false)
{
    ui->setupUi(this);
    QObject::connect(ui->button_request, &QPushButton::pressed, [&]  {
        has_offset = true;
        emit request_signal();
    });
}

View::~View()
{
    for (int i = 0; i < bulletins_vector.size(); i++)
        delete bulletins_vector[i];
    delete ui;
}

void View::build_bulletin(std::string *ret, const std::string &name,
                          const std::string &version, int max)
{
    int n_total;
    size_t n;
    std::vector<std::string> cve;
    std::vector<std::string> cpe;

    if (!has_offset) {
        for (int i = 0; i < bulletins_vector.size(); i++) {
            ui->layout_scroll->removeWidget(bulletins_vector[i]);
            delete bulletins_vector[i];
        }
        bulletins_vector.clear();
        ui->layout_scroll->update();
        offset = 0;
    }

    nlohmann::json js = nlohmann::json::parse(ret->std::string::erase(0, (ret->std::string::find("\r\n\r\n") + 4)));
    n_total = js["data"]["total"];
    if ((max + offset) > n_total)
        max = n_total - offset;
    if (n_total != 0) {
        for (int i = 0; i < max; i++) {
            std::vector<std::string>().swap(cve);
            for (n = 0; n < js["data"]["search"][i]["highlight"]["cvelist"].size(); n++)
                cve.push_back(js["data"]["search"][i]["highlight"]["cvelist"][n]);
            if (js["data"]["search"][i]["_source"]["type"] == "cve") {
                std::vector<std::string>().swap(cpe);
                for (n = 0; n < js["data"]["search"][i]["highlight"]["cpe"].size(); n++)
                    cpe.push_back(js["data"]["search"][i]["highlight"]["cpe"][n]);
                bulletins_vector.push_back(new Bulletin(true, false, this));
                bulletins_vector[offset]->set_number(offset + 1);
                bulletins_vector[offset]->set_published(js["data"]["search"][i]["_source"]["modified"]);
                bulletins_vector[offset]->set_title(js["data"]["search"][i]["flatDescription"], name, version, true, false);
                bulletins_vector[offset]->set_score(js["data"]["search"][i]["_source"]["cvss"]["score"]);
                bulletins_vector[offset]->set_description_cve(js["data"]["search"][i]["_source"]["description"], cve, false);
                bulletins_vector[offset]->set_id(js["data"]["search"][i]["_source"]["id"]);
                bulletins_vector[offset]->set_cvss(js["data"]["search"][i]["_source"]["cvss"]["vector"]);
                bulletins_vector[offset]->set_cpe(cpe);
                bulletins_vector[offset]->set_href(js["data"]["search"][i]["_source"]["href"]);
            } else if (js["data"]["search"][i]["_source"]["type"] == "exploitdb") {
                bulletins_vector.push_back(new Bulletin(false, true, this));
                bulletins_vector[offset]->set_number(offset + 1);
                bulletins_vector[offset]->set_published(js["data"]["search"][i]["_source"]["modified"]);
                bulletins_vector[offset]->set_title(js["data"]["search"][i]["_source"]["title"], name, version, false, true);
                bulletins_vector[offset]->set_score(js["data"]["search"][i]["_source"]["cvss"]["score"]);
                bulletins_vector[offset]->set_description_cve(js["data"]["search"][i]["_source"]["description"], cve, true);
                bulletins_vector[offset]->set_id(js["data"]["search"][i]["_source"]["id"]);
                bulletins_vector[offset]->set_cvss(js["data"]["search"][i]["_source"]["cvss"]["vector"]);
                bulletins_vector[offset]->set_source(js["data"]["search"][i]["_source"]["sourceData"], false);
                QObject::connect(bulletins_vector[offset], &Bulletin::status_signal, [&] (QString status) {
                    emit status_signal(status);
                });
            } else if (js["data"]["search"][i]["_source"]["type"] == "packetstorm") {
                bulletins_vector.push_back(new Bulletin(false, true, this));
                bulletins_vector[offset]->set_number(offset + 1);
                bulletins_vector[offset]->set_published(js["data"]["search"][i]["_source"]["modified"]);
                bulletins_vector[offset]->set_title(js["data"]["search"][i]["_source"]["title"], name, version, false, false);
                bulletins_vector[offset]->set_score(js["data"]["search"][i]["_source"]["cvss"]["score"]);
                bulletins_vector[offset]->set_description_cve(js["data"]["search"][i]["_source"]["title"], cve, false);
                bulletins_vector[offset]->set_id(js["data"]["search"][i]["_source"]["id"]);
                bulletins_vector[offset]->set_cvss(js["data"]["search"][i]["_source"]["cvss"]["vector"]);
                bulletins_vector[offset]->set_source(js["data"]["search"][i]["_source"]["sourceData"], true);
                QObject::connect(bulletins_vector[offset], &Bulletin::status_signal, [&] (QString status) {
                    emit status_signal(status);
                });
            } else {
                bulletins_vector.push_back(new Bulletin(false, false, this));
                bulletins_vector[offset]->set_number(offset + 1);
                bulletins_vector[offset]->set_published(js["data"]["search"][i]["_source"]["modified"]);
                bulletins_vector[offset]->set_title(js["data"]["search"][i]["_source"]["title"], name, version, false, true);
                bulletins_vector[offset]->set_score(js["data"]["search"][i]["_source"]["cvss"]["score"]);
                bulletins_vector[offset]->set_description_cve(js["data"]["search"][i]["_source"]["description"], cve, false);
                bulletins_vector[offset]->set_id(js["data"]["search"][i]["_source"]["id"]);
                bulletins_vector[offset]->set_cvss(js["data"]["search"][i]["_source"]["cvss"]["vector"]);
                bulletins_vector[offset]->set_href(js["data"]["search"][i]["_source"]["href"]);
                QObject::connect(bulletins_vector[offset], &Bulletin::status_signal, [&] (QString status) {
                    emit status_signal(status);
                });
            }
            ui->layout_scroll->addWidget(bulletins_vector.last());
            offset++;
        }
        ui->layout_scroll->update();
        if (offset > n_total)
            offset = n_total;
        ui->label_counter->setText(QString::number(offset) +
                                   "<span style=color:#808080>/</span>" +
                                   QString::number(n_total));
        ui->label_counter->setVisible(true);
        ui->button_request->setVisible(offset != n_total);
    } else {
        ui->label_counter->setText("0<span style=color:#808080>/</span>0");
        ui->label_counter->setVisible(true);
        ui->button_request->setHidden(true);
    }

    has_offset = false;
}

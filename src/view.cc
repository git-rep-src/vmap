#include "view.h"

#include "json.cc"

#include <vector>

#include <QScrollBar>

View::View(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::View)
{
    ui->setupUi(this);
}

View::~View()
{
    for (int i = 0; i < bulletins_vector.size(); i++)
        delete bulletins_vector[i];
    delete ui;
}

void View::build_bulletin(std::string *ret, const std::string &name,
                          const std::string &version, int max,
                          bool has_offset)
{
    size_t n;
    std::vector<std::string> cve;
    std::vector<std::string> cpe;

    if (!has_offset) {
        for (int i = 0; i < bulletins_vector.size(); i++) {
            ui->scroll_layout->removeWidget(bulletins_vector[i]);
            delete bulletins_vector[i];
        }
        bulletins_vector.clear();
        ui->scroll_layout->update();
        offset = 0;
        n_total = 0;
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
                QObject::connect(bulletins_vector[offset], &Bulletin::status_signal, [&] (const std::string status) {
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
                QObject::connect(bulletins_vector[offset], &Bulletin::status_signal, [&] (const std::string status) {
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
                QObject::connect(bulletins_vector[offset], &Bulletin::status_signal, [&] (const std::string status) {
                    emit status_signal(status);
                });
            }
            ui->scroll_layout->addWidget(bulletins_vector.last());
            offset++;
        }
        if (!has_offset)
            ui->scroll_area->verticalScrollBar()->setValue(0);
        ui->scroll_layout->update();
        if (offset > n_total)
            offset = n_total;
        emit counter_signal(offset, n_total);
    } else {
        emit counter_signal(0, 0);
    }
}

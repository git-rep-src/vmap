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
    for (int i = 0; i < element_vector.size(); i++)
        delete element_vector[i];
    delete ui;
}

void View::element(std::string *ret, int max)
{
    int n_total;
    size_t n;
    std::vector<std::string> cve;
    std::vector<std::string> cpe;

    if (!has_offset) {
        for (int i = 0; i < element_vector.size(); i++) {
            ui->layout_scroll->removeWidget(element_vector[i]);
            delete element_vector[i];
        }
        element_vector.clear();
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
                element_vector.push_back(new Element(true, false, this));
                element_vector[offset]->set_number(offset + 1);
                element_vector[offset]->set_published(js["data"]["search"][i]["_source"]["modified"]);
                element_vector[offset]->set_title(js["data"]["search"][i]["flatDescription"], true, false);
                element_vector[offset]->set_score(js["data"]["search"][i]["_source"]["cvss"]["score"]);
                element_vector[offset]->set_description_cve(js["data"]["search"][i]["_source"]["description"], cve, false);
                element_vector[offset]->set_id(js["data"]["search"][i]["_source"]["id"]);
                element_vector[offset]->set_cvss(js["data"]["search"][i]["_source"]["cvss"]["vector"]);
                element_vector[offset]->set_cpe(cpe);
                element_vector[offset]->set_href(js["data"]["search"][i]["_source"]["href"]);
            } else if (js["data"]["search"][i]["_source"]["type"] == "exploitdb") {
                element_vector.push_back(new Element(false, true, this));
                element_vector[offset]->set_number(offset + 1);
                element_vector[offset]->set_published(js["data"]["search"][i]["_source"]["modified"]);
                element_vector[offset]->set_title(js["data"]["search"][i]["_source"]["title"], false, true);
                element_vector[offset]->set_score(js["data"]["search"][i]["_source"]["cvss"]["score"]);
                element_vector[offset]->set_description_cve(js["data"]["search"][i]["_source"]["description"], cve, true);
                element_vector[offset]->set_id(js["data"]["search"][i]["_source"]["id"]);
                element_vector[offset]->set_cvss(js["data"]["search"][i]["_source"]["cvss"]["vector"]);
                element_vector[offset]->set_source(js["data"]["search"][i]["_source"]["sourceData"], false);
                QObject::connect(element_vector[offset], &Element::send_status_signal, [&] (QString status) {
                    emit send_status_signal(status);
                });
            } else if (js["data"]["search"][i]["_source"]["type"] == "packetstorm") {
                element_vector.push_back(new Element(false, true, this));
                element_vector[offset]->set_number(offset + 1);
                element_vector[offset]->set_published(js["data"]["search"][i]["_source"]["modified"]);
                element_vector[offset]->set_title(js["data"]["search"][i]["_source"]["title"], false, false);
                element_vector[offset]->set_score(js["data"]["search"][i]["_source"]["cvss"]["score"]);
                element_vector[offset]->set_description_cve(js["data"]["search"][i]["_source"]["title"], cve, false);
                element_vector[offset]->set_id(js["data"]["search"][i]["_source"]["id"]);
                element_vector[offset]->set_cvss(js["data"]["search"][i]["_source"]["cvss"]["vector"]);
                element_vector[offset]->set_source(js["data"]["search"][i]["_source"]["sourceData"], true);
                QObject::connect(element_vector[offset], &Element::send_status_signal, [&] (QString status) {
                    emit send_status_signal(status);
                });
            } else {
                element_vector.push_back(new Element(false, false, this));
                element_vector[offset]->set_number(offset + 1);
                element_vector[offset]->set_published(js["data"]["search"][i]["_source"]["modified"]);
                element_vector[offset]->set_title(js["data"]["search"][i]["_source"]["title"], false, true);
                element_vector[offset]->set_score(js["data"]["search"][i]["_source"]["cvss"]["score"]);
                element_vector[offset]->set_description_cve(js["data"]["search"][i]["_source"]["description"], cve, false);
                element_vector[offset]->set_id(js["data"]["search"][i]["_source"]["id"]);
                element_vector[offset]->set_cvss(js["data"]["search"][i]["_source"]["cvss"]["vector"]);
                element_vector[offset]->set_href(js["data"]["search"][i]["_source"]["href"]);
                QObject::connect(element_vector[offset], &Element::send_status_signal, [&] (QString status) {
                    emit send_status_signal(status);
                });
            }
            ui->layout_scroll->addWidget(element_vector.last());
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

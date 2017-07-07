#include "view.h"

#include "json.cc"

#include <vector>

#include <iostream>//

View::View(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::View),
    has_offset(false)
{
    ui->setupUi(this);
    QObject::connect(ui->request_button, &QPushButton::pressed, [&]  {
        has_offset = true;
        emit build_request_signal();
    });
}

View::~View()
{
    for (int i = 0; i < response_vector.size(); i++)
        delete response_vector[i];
    delete ui;
}

void View::show_data(std::string *ret, int max)
{
    int n_total;
    std::vector<std::string> cpe;
    std::vector<std::string> references;

    if (!has_offset) {
        for (int i = 0; i < response_vector.size(); i++) {
            ui->scroll_layout->removeWidget(response_vector[i]);
            delete response_vector[i];
        }
        response_vector.clear();
        ui->scroll_layout->update();
        offset = 0;
    }

    nlohmann::json js = nlohmann::json::parse(ret->std::string::erase(0, (ret->std::string::find("\r\n\r\n") + 4)));
    n_total = js["data"]["total"];
    if (n_total != 0) {
        for (int i = 0; i < max; i++) {
            offset++;
            if (js["data"]["search"][i]["_source"]["type"] == "cve") {
                std::vector<std::string>().swap(cpe);
                std::vector<std::string>().swap(references);
                for (size_t ii = 0; ii < js["data"]["search"][i]["_source"]["cpe"].size(); ii++)
                    cpe.push_back(js["data"]["search"][i]["_source"]["cpe"][ii]);
                for (size_t iii = 0; iii < js["data"]["search"][i]["_source"]["references"].size(); iii++)
                    references.push_back(js["data"]["search"][i]["_source"]["references"][iii]);
                response_vector.push_back(new Element(offset,
                                                      js["data"]["search"][i]["_source"]["published"],
                                                      js["data"]["search"][i]["flatDescription"],
                                                      js["data"]["search"][i]["_source"]["cvss"]["score"],
                                                      js["data"]["search"][i]["_source"]["description"],
                                                      js["data"]["search"][i]["_id"],
                                                      js["data"]["search"][i]["_source"]["cvss"]["vector"],
                                                      cpe,
                                                      references,
                                                      "",
                                                      this));
            } else if (js["data"]["search"][i]["_source"]["type"] == "exploitdb") {
                response_vector.push_back(new Element(offset,
                                                      js["data"]["search"][i]["_source"]["published"],
                                                      js["data"]["search"][i]["_source"]["title"],
                                                      js["data"]["search"][i]["_source"]["cvss"]["score"],
                                                      js["data"]["search"][i]["_source"]["description"],
                                                      js["data"]["search"][i]["_id"],
                                                      "",
                                                      cpe,
                                                      references,
                                                      js["data"]["search"][i]["_source"]["sourceData"],
                                                      this));
            }
            ui->scroll_layout->addWidget(response_vector.last());
        }
        ui->scroll_layout->update();
        ui->counter_label->setText(QString::number(offset) + "<span style=color:#808080>/</span>" + QString::number(n_total));
        ui->counter_label->setVisible(true);
        ui->request_button->setVisible(true);
    } else {
        ui->counter_label->setText("NO RESULT");
        ui->counter_label->setVisible(true);
        ui->request_button->setHidden(true);
    }

    has_offset = false;
}

#include "view.h"

#include "json.cc"

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

void View::show_data(std::string *ret)
{
    if (!has_offset) {
        for (int i = 0; i < response_vector.size(); i++) {
            ui->layout->removeWidget(response_vector[i]);
            delete response_vector[i];
        }
        response_vector.clear();
        ui->layout->update();
    }

    nlohmann::json js = nlohmann::json::parse(ret->std::string::erase(0, (ret->std::string::find("\r\n\r\n") + 4)));
    int n_total = js["data"]["total"];
    if (n_total != 0) {
        for (size_t i = 0; i < 10; i++) {
            if (js["data"]["search"][i]["_source"]["type"] == "cve") {
                response_vector.push_back(new Element(js["data"]["search"][i]["_source"]["published"],
                                                      js["data"]["search"][i]["flatDescription"],
                                                      js["data"]["search"][i]["_source"]["cvss"]["score"],
                                                      js["data"]["search"][i]["_source"]["description"],
                                                      js["data"]["search"][i]["_id"],
                                                      "", this));
            } else if (js["data"]["search"][i]["_source"]["type"] == "exploitdb") {
                response_vector.push_back(new Element(js["data"]["search"][i]["_source"]["published"],
                                                      js["data"]["search"][i]["_source"]["title"],
                                                      js["data"]["search"][i]["_source"]["cvss"]["score"],
                                                      js["data"]["search"][i]["_source"]["description"],
                                                      js["data"]["search"][i]["_id"],
                                                      js["data"]["search"][i]["_source"]["sourceData"], this));
            }
            ui->layout->addWidget(response_vector.last());
        }
        ui->layout->update();
        ui->counter_label->setText("5 - " + QString::number(n_total));
        ui->counter_label->setVisible(true);
        ui->request_button->setVisible(true);
    } else {
        ui->counter_label->setText("NO RESULT");
        ui->counter_label->setVisible(true);
        ui->request_button->setHidden(true);
    }

    has_offset = false;
}

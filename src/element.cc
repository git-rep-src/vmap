#include "element.h"

Element::Element(std::string published, std::string title,
                 float score, std::string description,
                 std::string id, std::string sourcedata,
                 QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Element)
{
    ui->setupUi(this);
    ui->published_label->setText(QString::fromStdString(published.std::string::erase(published.std::string::find("T"),
                                                                                     published.std::string::size())));
    ui->title_label->setText(QString::fromStdString(title));
    ui->score_label->setText(QString::number(score));
    ui->description_label->setText(QString::fromStdString(description));
    ui->id_label->setText(QString::fromStdString(id));
    ui->sourcedata_textedit->setPlainText(QString::fromStdString(sourcedata));
    QObject::connect(ui->details_button, &QPushButton::pressed, [=] {
        ui->description_label->setVisible(!ui->description_label->isVisible());
        ui->id_label->setVisible(!ui->id_label->isVisible());
        if (sourcedata != "") {
            ui->save_button->setVisible(!ui->save_button->isVisible());
            ui->sourcedata_textedit->setVisible(!ui->sourcedata_textedit->isVisible());
        }
    });
}

Element::~Element()
{
    delete ui;
}

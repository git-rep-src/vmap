#include "element.h"

Element::Element(int number, std::string published,
                 std::string title, float score,
                 std::string description, std::string id,
                 std::string vector, std::string sourcedata,
                 QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Element)
{
    ui->setupUi(this);

    bool is_exploit = (sourcedata != "");

    process(published, title, vector, is_exploit);

    ui->number_label->setText(QString("%1").arg(number, 5, 10, QChar('0')));
    ui->published_label->setText(QString::fromStdString(published));
    ui->title_label->setText(QString::fromStdString(title));
    if (score >= 7)
        ui->score_label->setProperty("type", "score-high");
    else if ((score >= 4) && (score < 7))
        ui->score_label->setProperty("type", "score-medium");
    ui->score_label->setText(QString::number(score));
    ui->description_label->setText(QString::fromStdString(description));
    ui->id_label->setText(QString::fromStdString(id));
    ui->vector_label->setText(QString::fromStdString(vector));
    ui->sourcedata_textedit->setPlainText(QString::fromStdString(sourcedata));

    QObject::connect(ui->details_button, &QPushButton::pressed, [=] {
        ui->description_label->setVisible(!ui->description_label->isVisible());
        ui->id_label->setVisible(!ui->id_label->isVisible());
        if (ui->description_label->isVisible())
            ui->details_button->setIcon(QIcon(":/icon-less"));
        else
            ui->details_button->setIcon(QIcon(":/icon-more"));
        if (is_exploit) {
            ui->save_button->setVisible(!ui->save_button->isVisible());
            ui->sourcedata_textedit->setVisible(!ui->sourcedata_textedit->isVisible());
        } else {
            ui->vector_label->setVisible(!ui->vector_label->isVisible());
        }
    });
}

Element::~Element()
{
    delete ui;
}

void Element::process(std::string &published, std::string &title,
                      std::string &vector, bool is_exploit)
{
    std::size_t n;

    if (published.std::string::find("T") != std::string::npos)
        published.std::string::erase(published.std::string::find("T"),
                                     published.std::string::size());

    if (title.std::string::size() >= (size_t)ui->title_label->width())
        title.std::string::replace((ui->title_label->width() - 3),
                                   (title.std::string::size() - (ui->title_label->width() - 3)),
                                   "...");

    if (is_exploit) {
        bool has_quotes = false;
        if ((n = title.std::string::find("<")) != std::string::npos)
            title.std::string::replace(n, 1, "&lt;");
        if ((n = title.std::string::find(">")) != std::string::npos)
            title.std::string::replace(n, 1, "&gt;");
        if ((n = title.std::string::rfind("'")) != std::string::npos) {
            title.std::string::insert((n + 1), "<a style=color:#677083 style=background-color:#373b45> ");
            title.std::string::insert(title.std::string::size(), " </a>");
            title.std::string::replace(n, 1, " ");
            title.std::string::replace(title.std::string::find("'"), 1, " ");
            has_quotes = true;
        }
        if ((n = title.std::string::rfind(" - ")) != std::string::npos) {
            if (!has_quotes) {
                title.std::string::insert((n + 1), "<a style=color:#677083 style=background-color:#373b45> ");
                title.std::string::insert(title.std::string::size(), " </a>");
            }
            title.std::string::replace(title.std::string::rfind(" - "), 2, " ");
        }
    } else {
        if ((n = vector.std::string::find("AV:")) != std::string::npos)
            vector.std::string::replace(n, 3, "<font color=#808080>VECTOR</font> ");
        if ((n = vector.std::string::find("/AC:")) != std::string::npos)
            vector.std::string::replace(n, 4, "&nbsp;&nbsp;&nbsp;<font color=#808080>COMPLEXITY</font> ");
        if ((n = vector.std::string::find("/Au:")) != std::string::npos)
            vector.std::string::erase(n, (vector.std::string::find("/C") - n));
        if ((n = vector.std::string::find("/C:")) != std::string::npos)
            vector.std::string::replace(n, 3, "&nbsp;&nbsp;&nbsp;<font color=#808080>CONFIDENTIALITY</font> ");
        if ((n = vector.std::string::find("/I:")) != std::string::npos)
            vector.std::string::replace(n, 3, "&nbsp;&nbsp;&nbsp;<font color=#808080>INTEGRITY</font> ");
        if ((n = vector.std::string::find("/A:")) != std::string::npos)
            vector.std::string::replace(n, 3, "&nbsp;&nbsp;&nbsp;<font color=#808080>AVAILABILITY</font> ");
        if ((n = vector.std::string::rfind("/")) != std::string::npos)
            vector.std::string::erase(n, 1);
    }
}
